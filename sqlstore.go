package sqlstore

import (
	"database/sql"
	"encoding/base32"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/admpub/errors"
	"github.com/admpub/null"
	"github.com/admpub/securecookie"
	"github.com/admpub/sessions"
	"github.com/webx-top/echo"
	"github.com/webx-top/echo/middleware/session/engine"
	ss "github.com/webx-top/echo/middleware/session/engine"
)

type Options struct {
	Table         string        `json:"table"`
	KeyPrefix     string        `json:"keyPrefix"`
	KeyPairs      [][]byte      `json:"-"`
	MaxAge        int           `json:"maxAge"`
	EmptyDataAge  int           `json:"emptyDataAge"`
	MaxLength     int           `json:"maxLength"`
	CheckInterval time.Duration `json:"checkInterval"`
	MaxReconnect  int           `json:"maxReconnect"`
	ddl           string
}

func (o *Options) SetDDL(ddl string) *Options {
	o.ddl = ddl
	return o
}

type SQLStore struct {
	db             *sql.DB
	stmtInsert     *sql.Stmt
	stmtDelete     *sql.Stmt
	stmtUpdate     *sql.Stmt
	stmtSelect     *sql.Stmt
	gcMaxAgeSQL    string
	gcEmptyDataSQL string

	Codecs        []securecookie.Codec
	table         string
	maxAge        int
	emptyDataAge  int
	checkInterval time.Duration
	keyPrefix     string
	quiteC        chan<- struct{}
	doneC         <-chan struct{}
	once          sync.Once
}

type sessionRow struct {
	id       null.String
	data     null.Bytes
	created  null.Int64
	modified null.Int64
	expires  null.Int64
}

// New .
func New(db *sql.DB, cfg *Options) (*SQLStore, error) {
	if len(cfg.Table) == 0 {
		cfg.Table = `session`
	}
	// Make sure table name is enclosed.
	tableName := "`" + strings.Trim(cfg.Table, "`") + "`"

	cTableQ := fmt.Sprintf(cfg.ddl, tableName)
	if _, err := db.Exec(cTableQ); err != nil {
		return nil, errors.Wrap(err, cTableQ)
	}

	insQ := "REPLACE INTO " + tableName +
		"(id, data, created, modified, expires) VALUES (?, ?, ?, ?, ?)"
	stmtInsert, stmtErr := db.Prepare(insQ)
	if stmtErr != nil {
		return nil, errors.Wrap(stmtErr, insQ)
	}

	delQ := "DELETE FROM " + tableName + " WHERE id = ?"
	stmtDelete, stmtErr := db.Prepare(delQ)
	if stmtErr != nil {
		return nil, errors.Wrap(stmtErr, delQ)
	}

	updQ := "UPDATE " + tableName + " SET data = ?, created = ?, expires = ? " +
		"WHERE id = ?"
	stmtUpdate, stmtErr := db.Prepare(updQ)
	if stmtErr != nil {
		return nil, errors.Wrap(stmtErr, updQ)
	}

	selQ := "SELECT id, data, created, modified, expires from " +
		tableName + " WHERE id = ?"
	stmtSelect, stmtErr := db.Prepare(selQ)
	if stmtErr != nil {
		return nil, errors.Wrap(stmtErr, selQ)
	}
	s := &SQLStore{
		db:             db,
		stmtInsert:     stmtInsert,
		stmtDelete:     stmtDelete,
		stmtUpdate:     stmtUpdate,
		stmtSelect:     stmtSelect,
		gcMaxAgeSQL:    "DELETE FROM " + tableName + " WHERE expires < ",
		gcEmptyDataSQL: "DELETE FROM " + tableName + " WHERE char_length(data) = " + strconv.Itoa(sessions.EmptyGobSize()) + " AND created < ",
		Codecs:         securecookie.CodecsFromPairs(cfg.KeyPairs...),
		table:          tableName,
		maxAge:         cfg.MaxAge,
		emptyDataAge:   cfg.EmptyDataAge,
		keyPrefix:      cfg.KeyPrefix,
		checkInterval:  cfg.CheckInterval,
	}
	if cfg.MaxLength > 0 {
		s.MaxLength(cfg.MaxLength)
	}
	if len(s.keyPrefix) == 0 {
		s.keyPrefix = `_`
	}
	if s.emptyDataAge <= 0 {
		s.emptyDataAge = engine.EmptyDataAge
	}
	return s, nil
}

func (m *SQLStore) Close() (err error) {
	m.stmtSelect.Close()
	m.stmtUpdate.Close()
	m.stmtDelete.Close()
	m.stmtInsert.Close()
	err = m.db.Close()
	m.closeCleanup()
	return
}

func (m *SQLStore) Get(ctx echo.Context, name string) (*sessions.Session, error) {
	m.Init()
	return sessions.GetRegistry(ctx).Get(m, name)
}

func (m *SQLStore) New(ctx echo.Context, name string) (*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	session.IsNew = true
	var err error
	value := ctx.GetCookie(name)
	if len(value) == 0 {
		return session, err
	}
	err = securecookie.DecodeMulti(name, value, &session.ID, m.Codecs...)
	if err != nil {
		return session, err
	}
	err = m.load(session)
	if err == nil {
		session.IsNew = false
	} else if err == sql.ErrNoRows || err == ErrSessionExpired {
		err = nil
	}
	return session, err
}

func (m *SQLStore) Reload(ctx echo.Context, session *sessions.Session) error {
	err := m.load(session)
	if err == nil {
		session.IsNew = false
	} else if err == sql.ErrNoRows || err == ErrSessionExpired {
		err = nil
	}
	return err
}

func (m *SQLStore) Save(ctx echo.Context, session *sessions.Session) error {
	var err error
	// Delete if max-age is < 0
	if ctx.CookieOptions().MaxAge < 0 {
		return m.Delete(ctx, session)
	}
	if len(session.ID) == 0 {
		// generate random session ID key suitable for storage in the db
		session.ID = strings.TrimRight(
			base32.StdEncoding.EncodeToString(
				securecookie.GenerateRandomKey(32)), "=")
		if err = m.insert(ctx, session); err != nil {
			return err
		}
	} else if err = m.save(ctx, session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, m.Codecs...)
	if err != nil {
		return err
	}
	sessions.SetCookie(ctx, session.Name(), encoded)
	return nil
}

func (m *SQLStore) Remove(sessionID string) error {
	if len(sessionID) == 0 {
		return nil
	}
	_, delErr := m.stmtDelete.Exec(sessionID)
	return delErr
}

func (m *SQLStore) insert(ctx echo.Context, session *sessions.Session) error {
	var modifiedAt int64
	var createdAt int64
	var expiredAt int64
	nowTs := time.Now().Unix()
	created := session.Values[m.keyPrefix+"created"]
	if created == nil {
		createdAt = nowTs
	} else {
		createdAt = created.(int64)
	}
	modifiedAt = createdAt
	expires := session.Values[m.keyPrefix+"expires"]
	if expires == nil {
		expiredAt = nowTs + int64(m.MaxAge(ctx))
	} else {
		expiredAt = expires.(int64)
	}
	delete(session.Values, m.keyPrefix+"created")
	delete(session.Values, m.keyPrefix+"expires")
	delete(session.Values, m.keyPrefix+"modified")

	encoded, err := securecookie.Gob.Serialize(session.Values)
	if err != nil {
		return err
	}
	_, insErr := m.stmtInsert.Exec(session.ID, encoded, createdAt, modifiedAt, expiredAt)
	return insErr
}

func (m *SQLStore) Delete(ctx echo.Context, session *sessions.Session) error {
	sessions.SetCookie(ctx, session.Name(), ``, -1)
	// Clear session values.
	for k := range session.Values {
		delete(session.Values, k)
	}
	return m.Remove(session.ID)
}

func (n *SQLStore) MaxAge(ctx echo.Context) int {
	maxAge := ctx.CookieOptions().MaxAge
	if maxAge == 0 {
		if n.maxAge > 0 {
			maxAge = n.maxAge
		} else {
			maxAge = ss.DefaultMaxAge
		}
	}
	return maxAge
}

// MaxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default for a new FilesystemStore is 4096.
func (s *SQLStore) MaxLength(l int) {
	securecookie.SetMaxLength(s.Codecs, l)
}

func (m *SQLStore) save(ctx echo.Context, session *sessions.Session) error {
	if session.IsNew {
		return m.insert(ctx, session)
	}
	var createdAt int64
	var expiredAt int64
	nowTs := time.Now().Unix()
	created := session.Values[m.keyPrefix+"created"]
	if created == nil {
		createdAt = nowTs
	} else {
		createdAt = created.(int64)
	}

	expires := session.Values[m.keyPrefix+"expires"]
	maxAge := int64(m.MaxAge(ctx))
	if expires == nil {
		expiredAt = nowTs + maxAge
	} else {
		expiredAt = expires.(int64)
		expiresTs := nowTs + maxAge
		if expiredAt < expiresTs {
			expiredAt = expiresTs
		}
	}

	delete(session.Values, m.keyPrefix+"created")
	delete(session.Values, m.keyPrefix+"expires")
	delete(session.Values, m.keyPrefix+"modified")
	encoded, err := securecookie.Gob.Serialize(session.Values)
	if err != nil {
		return err
	}
	//encoded := string(b)
	_, updErr := m.stmtUpdate.Exec(encoded, createdAt, expiredAt, session.ID)
	if updErr != nil {
		return updErr
	}
	return nil
}

var ErrSessionExpired = errors.New("Session expired")

func (m *SQLStore) load(session *sessions.Session) error {
	row := m.stmtSelect.QueryRow(session.ID)
	sess := sessionRow{}
	scanErr := row.Scan(&sess.id, &sess.data, &sess.created, &sess.modified, &sess.expires)
	if scanErr != nil {
		return scanErr
	}
	if sess.expires.Int64 < time.Now().Unix() {
		log.Printf("Session expired on %s, but it is %s now.", time.Unix(sess.expires.Int64, 0), time.Now())
		return ErrSessionExpired
	}
	err := securecookie.Gob.Deserialize(sess.data.Bytes, &session.Values)
	if err != nil {
		return err
	}
	session.Values[m.keyPrefix+"created"] = sess.created.Int64
	session.Values[m.keyPrefix+"modified"] = sess.modified.Int64
	session.Values[m.keyPrefix+"expires"] = sess.expires.Int64
	return nil

}

func (m *SQLStore) closeCleanup() {
	// Invoke a reaper which checks and removes expired sessions periodically.
	if m.quiteC != nil && m.doneC != nil {
		m.StopCleanup(m.quiteC, m.doneC)
	}
}

func (m *SQLStore) Init() {
	m.once.Do(m.init)
}

func (m *SQLStore) init() {
	m.closeCleanup()
	m.quiteC, m.doneC = m.Cleanup(m.checkInterval)
}
