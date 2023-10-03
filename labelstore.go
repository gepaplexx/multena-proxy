package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/fsnotify/fsnotify"
	"github.com/go-sql-driver/mysql"
	"github.com/spf13/viper"
)

// Labelstore represents an interface defining methods for connecting to a
// label store and retrieving labels associated with a given OAuth token.
type Labelstore interface {
	// Connect establishes a connection with the label store using App configuration.
	Connect(App) error
	// GetLabels retrieves labels associated with the provided OAuth token.
	// Returns a map containing the labels and a boolean indicating whether
	// the label is cluster-wide or not.
	GetLabels(token OAuthToken) (map[string]bool, bool)
}

// WithLabelStore initializes and connects to a LabelStore specified in the
// application configuration. It assigns the connected LabelStore to the App
// instance and returns it. If the LabelStore type is unknown or an error
// occurs during the connection, it logs a fatal error.
func (a *App) WithLabelStore() *App {
	switch a.Cfg.Web.LabelStoreKind {
	case "configmap":
		a.LabelStore = &ConfigMapHandler{}
	case "mysql":
		a.LabelStore = &MySQLHandler{}
	default:
		log.Fatal().Str("type", a.Cfg.Web.LabelStoreKind).Msg("Unknown label store type")
	}
	err := a.LabelStore.Connect(*a)
	if err != nil {
		log.Fatal().Err(err).Msg("Error connecting to labelstore")
	}
	return a
}

type ConfigMapHandler struct {
	labels map[string]map[string]bool
}

func (c *ConfigMapHandler) Connect(_ App) error {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigName("labels")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/config/labels/")
	v.AddConfigPath("./configs")
	err := v.MergeInConfig()
	if err != nil {
		return err
	}
	err = v.Unmarshal(&c.labels)
	if err != nil {
		log.Fatal().Err(err).Msg("Error while unmarshalling config file")
		return err
	}
	v.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("Config file changed")
		err = v.MergeInConfig()
		if err != nil {
			log.Fatal().Err(err).Msg("Error while unmarshalling config file")
		}
		err = v.Unmarshal(&c.labels)
		if err != nil {
			log.Fatal().Err(err).Msg("Error while unmarshalling config file")
		}
	})
	v.WatchConfig()
	log.Debug().Any("labels", c.labels).Msg("")
	return nil
}

func (c *ConfigMapHandler) GetLabels(token OAuthToken) (map[string]bool, bool) {
	username := token.PreferredUsername
	groups := token.Groups
	mergedNamespaces := make(map[string]bool, len(c.labels[username])*2)
	for k := range c.labels[username] {
		mergedNamespaces[k] = true
		if k == "#cluster-wide" {
			return nil, true
		}
	}
	for _, group := range groups {
		for k := range c.labels[group] {
			mergedNamespaces[k] = true
			if k == "#cluster-wide" {
				return nil, true
			}
		}
	}
	return mergedNamespaces, false
}

type MySQLHandler struct {
	DB       *sql.DB
	Query    string
	TokenKey string
}

func (m *MySQLHandler) Connect(a App) error {
	password, err := os.ReadFile(a.Cfg.Db.PasswordPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not read db password")
	}
	cfg := mysql.Config{
		User:                 a.Cfg.Db.User,
		Passwd:               string(password),
		Net:                  "tcp",
		AllowNativePasswords: true,
		Addr:                 fmt.Sprintf("%s:%d", a.Cfg.Db.Host, a.Cfg.Db.Port),
		DBName:               a.Cfg.Db.DbName,
	}
	// Get a database handle.
	m.DB, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal().Err(err).Msg("Error opening DB connection")
	}
	return nil
}

func (m *MySQLHandler) Close() {
	err := m.DB.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("Error closing DB connection")
	}
}

func (m *MySQLHandler) GetLabels(token OAuthToken) (map[string]bool, bool) {
	tokenMap := map[string]string{
		"email":             token.Email,
		"preferredUsername": token.PreferredUsername,
		"groups":            strings.Join(token.Groups, ","),
	}

	value, ok := tokenMap[m.TokenKey]
	if !ok {
		log.Fatal().Str("property", m.TokenKey).Msg("Unsupported token property")
		return nil, false
	}
	n := strings.Count(m.Query, "?")

	var params []any
	for i := 0; i < n; i++ {
		params = append(params, value)
	}

	res, err := m.DB.Query(m.Query, params...)
	defer func(res *sql.Rows) {
		err := res.Close()
		if err != nil {
			log.Fatal().Err(err).Msg("Error closing DB result")
		}
	}(res)
	if err != nil {
		log.Fatal().Err(err).Msg("Error while querying database")
	}
	labels := make(map[string]bool)
	for res.Next() {
		var label string
		err = res.Scan(&label)
		labels[label] = true
		if err != nil {
			log.Fatal().Err(err).Msg("Error scanning DB result")
		}
	}
	return labels, false
}
