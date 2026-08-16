package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/certificates"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/preflight"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"golang.org/x/sys/unix"
)

const JournalSchema = "lanpanel.headscale.control-journal.v1"

type Phase string

const (
	PhasePrepared           Phase = "prepared"
	PhaseDatabaseCommitted  Phase = "database_committed"
	PhaseServiceStaged      Phase = "service_staged"
	PhaseCertificatePending Phase = "certificate_pending"
	PhaseCertificateStaged  Phase = "certificate_staged"
	PhaseActivationIntent   Phase = "activation_intent"
	PhaseActivated          Phase = "activated"
	PhaseContracted         Phase = "contracted"
)

type DatabaseEvidence struct {
	UUID              string `json:"uuid"`
	Generation        uint64 `json:"generation"`
	MainDigest        string `json:"main_digest"`
	WALDigest         string `json:"wal_digest,omitempty"`
	SHMDigest         string `json:"shm_digest,omitempty"`
	JournalDigest     string `json:"journal_digest,omitempty"`
	InitializedDigest string `json:"initialized_digest"`
}

type ServiceEvidence struct {
	Identity       string `json:"identity"`
	PrivateProbe   string `json:"private_probe"`
	PublicSTUNOpen bool   `json:"public_stun_open"`
}

type Journal struct {
	SchemaVersion    string                     `json:"schema_version"`
	InstallationID   string                     `json:"installation_id"`
	JobID            string                     `json:"job_id"`
	PlanID           string                     `json:"plan_id"`
	IntentGeneration uint64                     `json:"intent_generation"`
	Candidate        Candidate                  `json:"candidate"`
	CandidateDigest  string                     `json:"candidate_digest"`
	Preflight        preflight.ExpansionRequest `json:"preflight"`
	PreflightDigest  string                     `json:"preflight_digest"`
	Phase            Phase                      `json:"phase"`
	Database         *DatabaseEvidence          `json:"database,omitempty"`
	Service          *ServiceEvidence           `json:"service,omitempty"`
	Certificate      *certificates.Identity     `json:"certificate,omitempty"`
	ActivationDigest string                     `json:"activation_digest,omitempty"`
	RuntimeDigest    string                     `json:"runtime_digest,omitempty"`
}

type Store struct {
	paths Paths
	owner filetxn.Owner
}

func NewStore(paths Paths, owner filetxn.Owner) *Store { return &Store{paths: paths, owner: owner} }

func NewJournal(installationID, jobID, planID string, intentGeneration uint64, candidate Candidate, request preflight.ExpansionRequest) (Journal, error) {
	candidateDigest, err := Digest(candidate)
	if err != nil {
		return Journal{}, err
	}
	preflightDigest, err := preflight.ExpansionRequestDigest(request)
	if err != nil {
		return Journal{}, err
	}
	value := Journal{SchemaVersion: JournalSchema, InstallationID: installationID, JobID: jobID, PlanID: planID, IntentGeneration: intentGeneration, Candidate: candidate, CandidateDigest: candidateDigest, Preflight: request, PreflightDigest: preflightDigest, Phase: PhasePrepared}
	if err := ValidateJournal(value); err != nil {
		return Journal{}, err
	}
	return value, nil
}

func ValidateJournal(value Journal) error {
	if value.SchemaVersion != JournalSchema || value.InstallationID == "" || value.JobID == "" || value.PlanID == "" || value.IntentGeneration == 0 || Validate(value.Candidate) != nil {
		return fmt.Errorf("Headscale control journal authority is invalid")
	}
	candidateDigest, err := Digest(value.Candidate)
	if err != nil || candidateDigest != value.CandidateDigest {
		return fmt.Errorf("Headscale control journal candidate changed")
	}
	preflightDigest, err := preflight.ExpansionRequestDigest(value.Preflight)
	if err != nil || preflightDigest != value.PreflightDigest || value.Preflight.Scope != preflight.ExpansionHeadscale || value.Preflight.Target != "headscale" || value.Preflight.Generation != value.Candidate.DatabaseGeneration {
		return fmt.Errorf("Headscale control journal preflight changed")
	}
	switch value.Phase {
	case PhasePrepared:
		if value.Database != nil || value.Service != nil || value.Certificate != nil {
			return fmt.Errorf("prepared Headscale journal carries later evidence")
		}
	case PhaseDatabaseCommitted:
		if !validDatabase(value) || value.Service != nil || value.Certificate != nil {
			return fmt.Errorf("database Headscale journal evidence invalid")
		}
	case PhaseServiceStaged, PhaseCertificatePending:
		if !validDatabase(value) || !validService(value) || value.Certificate != nil {
			return fmt.Errorf("service Headscale journal evidence invalid")
		}
	case PhaseCertificateStaged, PhaseActivationIntent, PhaseActivated, PhaseContracted:
		if !validDatabase(value) || !validService(value) || value.Certificate != nil && (certificates.ValidateIdentity(*value.Certificate) != nil || value.Certificate.ID != value.Candidate.CertificateID || value.Certificate.BindingIdentity != value.Candidate.CertificateBinding || !slices.Equal(value.Certificate.Domains, []string{value.Candidate.ControlDomain})) || value.Phase != PhaseContracted && value.Certificate == nil {
			return fmt.Errorf("staged or contracted Headscale certificate evidence invalid")
		}
		if value.Phase == PhaseCertificateStaged && (value.ActivationDigest != "" || value.RuntimeDigest != "") || value.Phase == PhaseActivationIntent && (!digestValue(value.ActivationDigest) || value.RuntimeDigest != "") || value.Phase == PhaseActivated && (!digestValue(value.ActivationDigest) || !digestValue(value.RuntimeDigest)) || value.Phase == PhaseContracted && (value.ActivationDigest != "" && !digestValue(value.ActivationDigest) || value.RuntimeDigest != "") {
			return fmt.Errorf("Headscale activation evidence invalid")
		}
		if value.ActivationDigest != "" {
			bundle, bundleErr := BuildActivation(value.InstallationID, value.Candidate, *value.Certificate)
			if bundleErr != nil || bundle.Digest != value.ActivationDigest {
				return fmt.Errorf("Headscale activation bundle evidence changed")
			}
		}
	default:
		return fmt.Errorf("Headscale control journal phase invalid")
	}
	return nil
}

func validDatabase(value Journal) bool {
	return value.Database != nil && value.Database.UUID == value.Candidate.DatabaseUUID && value.Database.Generation == value.Candidate.DatabaseGeneration && digestValue(value.Database.MainDigest) && digestValue(value.Database.InitializedDigest) && optionalDigest(value.Database.WALDigest) && optionalDigest(value.Database.SHMDigest) && optionalDigest(value.Database.JournalDigest)
}
func optionalDigest(value string) bool { return value == "" || digestValue(value) }

func validService(value Journal) bool {
	return value.Service != nil && value.Service.Identity == value.Candidate.ServiceIdentity && digestValue(value.Service.PrivateProbe) && !value.Service.PublicSTUNOpen
}

func (store *Store) Create(ctx context.Context, value Journal) error {
	if err := ValidateJournal(value); err != nil || value.Phase != PhasePrepared {
		return errors.Join(err, fmt.Errorf("only a prepared Headscale control journal may be created"))
	}
	if err := store.ensureStaging(); err != nil {
		return err
	}
	data, _ := json.Marshal(value)
	transaction, err := store.open()
	if err != nil {
		return err
	}
	_, putErr := transaction.Put(ctx, filetxn.Request{Path: store.paths.Journal, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{store.owner}, AllowedMode: 0o755}, New: filetxn.Metadata{Owner: store.owner, Mode: 0o600}, MaxBytes: 1 << 20}, data, filetxn.CreateOnly)
	return errors.Join(putErr, transaction.Close())
}

func (store *Store) Replace(ctx context.Context, prior, next Journal) error {
	if err := ValidateJournal(prior); err != nil {
		return err
	}
	if err := ValidateJournal(next); err != nil {
		return err
	}
	if !sameJournalAuthority(prior, next) || !validPhaseAdvance(prior.Phase, next.Phase) {
		return fmt.Errorf("Headscale control journal transition invalid")
	}
	current, err := store.Read()
	if err != nil || !reflect.DeepEqual(current, prior) {
		return fmt.Errorf("Headscale control journal changed before replace")
	}
	data, _ := json.Marshal(next)
	transaction, err := store.open()
	if err != nil {
		return err
	}
	_, putErr := transaction.Put(ctx, filetxn.Request{Path: store.paths.Journal, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{store.owner}, AllowedMode: 0o755}, Existing: &filetxn.Metadata{Owner: store.owner, Mode: 0o600}, New: filetxn.Metadata{Owner: store.owner, Mode: 0o600}, MaxBytes: 1 << 20}, data, filetxn.ReplaceOnly)
	return errors.Join(putErr, transaction.Close())
}

func (store *Store) Contract(ctx context.Context, prior Journal) (Journal, error) {
	if err := ValidateJournal(prior); err != nil || (prior.Phase != PhaseCertificatePending && prior.Phase != PhaseCertificateStaged && prior.Phase != PhaseActivationIntent && prior.Phase != PhaseActivated && prior.Phase != PhaseContracted) {
		return Journal{}, fmt.Errorf("Headscale control journal is not contractible")
	}
	if prior.Phase == PhaseContracted {
		return prior, nil
	}
	next := prior
	next.Phase = PhaseContracted
	next.RuntimeDigest = ""
	if err := store.Replace(ctx, prior, next); err != nil {
		return Journal{}, err
	}
	return next, nil
}

func (store *Store) Read() (Journal, error) {
	fd, err := unix.Open(store.paths.Journal, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Journal{}, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(store.paths.Journal))
	if file == nil {
		_ = unix.Close(fd)
		return Journal{}, fmt.Errorf("Headscale control journal descriptor unavailable")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != store.owner.UID || stat.Gid != store.owner.GID || stat.Mode&0o7777 != 0o600 || stat.Size <= 0 || stat.Size > 1<<20 {
		return Journal{}, fmt.Errorf("Headscale control journal metadata is unsafe")
	}
	data := make([]byte, stat.Size)
	if _, err := file.ReadAt(data, 0); err != nil {
		return Journal{}, err
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || stat.Dev != after.Dev || stat.Ino != after.Ino || stat.Size != after.Size || stat.Mtim != after.Mtim {
		return Journal{}, fmt.Errorf("Headscale control journal changed during read")
	}
	var value Journal
	if json.Unmarshal(data, &value) != nil {
		return Journal{}, fmt.Errorf("Headscale control journal encoding invalid")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !slices.Equal(canonical, data) || ValidateJournal(value) != nil {
		return Journal{}, fmt.Errorf("Headscale control journal authority invalid")
	}
	return value, nil
}

func (store *Store) ensureStaging() error {
	if err := ensureFixedDirectory(store.paths.JournalRoot, store.owner, 0o700); err != nil {
		return err
	}
	if filepath.Dir(store.paths.JournalStaging) != store.paths.JournalRoot || filepath.Dir(store.paths.Journal) != store.paths.JournalRoot {
		return fmt.Errorf("Headscale control journal paths leave fixed state root")
	}
	parent, err := unix.Open(store.paths.JournalRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	name := filepath.Base(store.paths.JournalStaging)
	if err := unix.Mkdirat(parent, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	var stat unix.Stat_t
	if unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != store.owner.UID || stat.Gid != store.owner.GID || stat.Mode&0o7777 != 0o700 {
		return fmt.Errorf("Headscale control journal staging metadata is unsafe")
	}
	return unix.Fsync(parent)
}

func (store *Store) open() (*filetxn.Store, error) {
	return filetxn.Open(filetxn.Config{RootPath: store.paths.JournalRoot, Root: filetxn.Metadata{Owner: store.owner, Mode: 0o700}, StagingPath: store.paths.JournalStaging, Staging: filetxn.Metadata{Owner: store.owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{store.owner}, AllowedMode: 0o755}}, filetxn.Options{})
}

func sameJournalAuthority(left, right Journal) bool {
	left.Phase, right.Phase = "", ""
	left.Database, right.Database = nil, nil
	left.Service, right.Service = nil, nil
	left.Certificate, right.Certificate = nil, nil
	left.ActivationDigest, right.ActivationDigest = "", ""
	left.RuntimeDigest, right.RuntimeDigest = "", ""
	return reflect.DeepEqual(left, right)
}
func validPhaseAdvance(left, right Phase) bool {
	return left == PhasePrepared && right == PhaseDatabaseCommitted || left == PhaseDatabaseCommitted && right == PhaseServiceStaged || left == PhaseServiceStaged && right == PhaseCertificatePending || left == PhaseCertificatePending && right == PhaseCertificateStaged || left == PhaseCertificateStaged && right == PhaseActivationIntent || left == PhaseActivationIntent && right == PhaseActivated || (left == PhaseCertificatePending || left == PhaseCertificateStaged || left == PhaseActivationIntent || left == PhaseActivated) && right == PhaseContracted
}
