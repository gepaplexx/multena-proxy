package main

import (
	"database/sql"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/go-sql-driver/mysql"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"os"
	"strings"
)

type Labelstore interface {
	Connect(App) error
	//Close() error
	GetLabels(token KeycloakToken) map[string]bool
}

func (a *App) WithLabelStore() {
	switch a.Cfg.LabelStore.typ {
	case "configmap":
		a.LabelStore = &ConfigMapHandler{}
	case "mysql":
		a.LabelStore = &MySQLHandler{}
	default:
		Logger.Panic("Unknown labelstore type", zap.String("type", a.Cfg.LabelStore.typ))
	}
	err := a.LabelStore.Connect(*a)

	if err != nil {
		Logger.Panic("Error connecting to labelstore", zap.Error(err))
	}
}

type ConfigMapHandler struct {
	Users     map[string][]string `mapstructure:"users"`
	Groups    map[string][]string `mapstructure:"groups"`
	converted map[string]map[string]bool
}

func (c *ConfigMapHandler) Connect(a App) error {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigName("labels")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/config/labels/")
	v.AddConfigPath("./configs")
	err := v.MergeInConfig()
	if err != nil {
		return err
	}
	err = v.Unmarshal(c)
	if err != nil {
		Logger.Panic("Error while unmarshalling config file", zap.Error(err))
		return err
	}
	v.OnConfigChange(func(e fsnotify.Event) {
		Logger.Info("Config file changed", zap.String("file", e.Name))
		err = v.MergeInConfig()
		if err != nil {
			Logger.Panic("Error while unmarshalling config file", zap.Error(err))
		}
		err = v.Unmarshal(c)
		if err != nil {
			Logger.Panic("Error while unmarshalling config file", zap.Error(err))
		}

	})
	v.WatchConfig()
	c.convert()
	return nil
}

func (c *ConfigMapHandler) convert() {
	c.converted = make(map[string]map[string]bool, len(c.Users)+len(c.Groups))
	for username, namespaces := range c.Users {
		c.converted[username] = make(map[string]bool, len(namespaces))
		for _, namespace := range namespaces {
			c.converted[username][namespace] = true
		}
	}
	for group, namespaces := range c.Groups {
		c.converted[group] = make(map[string]bool, len(namespaces))
		for _, namespace := range namespaces {
			c.converted[group][namespace] = true
		}
	}
}

func (c *ConfigMapHandler) GetLabels(token KeycloakToken) map[string]bool {
	username := token.PreferredUsername
	groups := token.Groups
	mergedNamespaces := make(map[string]bool, len(c.converted[username])*2)
	for k, _ := range c.converted[username] {
		mergedNamespaces[k] = true
	}
	for _, group := range groups {
		for k, _ := range c.converted[group] {
			mergedNamespaces[k] = true
		}
	}
	return mergedNamespaces
}

type MySQLHandler struct {
	DB       *sql.DB
	Query    string
	TokenKey string
}

func (m *MySQLHandler) Connect(a App) error {
	password, err := os.ReadFile(a.Cfg.Db.PasswordPath)
	if err != nil {
		Logger.Panic("Could not read db password", zap.Error(err))
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
		Logger.Panic("Error opening DB connection", zap.Error(err))
	}
	return nil
}

func (m *MySQLHandler) Close() {
	err := m.DB.Close()
	if err != nil {
		Logger.Panic("Error closing DB connection", zap.Error(err))
	}
}

func (m *MySQLHandler) GetLabels(token KeycloakToken) map[string]bool {
	tokenMap := map[string]string{
		"email":             token.Email,
		"preferredUsername": token.PreferredUsername,
		"groups":            strings.Join(token.Groups, ","),
	}

	value, ok := tokenMap[m.TokenKey]
	if !ok {
		Logger.Panic("Unsupported token property", zap.String("property", m.TokenKey))
		return nil
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
			Logger.Panic("Error closing DB result", zap.Error(err))
		}
	}(res)
	if err != nil {
		Logger.Panic("Error while querying database", zap.Error(err))
	}
	labels := make(map[string]bool)
	for res.Next() {
		var label string
		err = res.Scan(&label)
		labels[label] = true
		if err != nil {
			Logger.Panic("Error scanning DB result", zap.Error(err))
		}
	}
	return labels
}
