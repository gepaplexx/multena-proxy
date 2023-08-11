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
	Connect() error
	//Close() error
	GetLabels(token KeycloakToken) map[string]bool
}

type ConfigMapHandler struct {
	Users      map[string][]string `mapstructure:"users"`
	Groups     map[string][]string `mapstructure:"groups"`
	_converted map[string]map[string]bool
}

func (c *ConfigMapHandler) Connect() {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigName("labels")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/config/labels/")
	v.AddConfigPath("./configs")
	err := v.Unmarshal(c)
	if err != nil {
		Logger.Panic("Error while unmarshalling config file", zap.Error(err))
	}
	v.OnConfigChange(func(e fsnotify.Event) {
		Logger.Info("Config file changed", zap.String("file", e.Name))
		err := v.Unmarshal(c)
		if err != nil {
			Logger.Panic("Error while unmarshalling config file", zap.Error(err))
		}

	})
	v.WatchConfig()

	c._converted = make(map[string]map[string]bool, len(c.Users)+len(c.Groups))
	for username, namespaces := range c.Users {
		c._converted[username] = make(map[string]bool, len(namespaces))
		for _, namespace := range namespaces {
			c._converted[username][namespace] = true
		}
	}
	for group, namespaces := range c.Groups {
		for _, namespace := range namespaces {
			c._converted[group][namespace] = true
		}
	}
}

func (c *ConfigMapHandler) GetLabels(token KeycloakToken) map[string]bool {
	username := token.PreferredUsername
	groups := token.Groups
	var mergedNamespaces map[string]bool
	for k, _ := range c._converted[username] {
		mergedNamespaces[k] = true
	}
	for _, group := range groups {
		for k, _ := range c._converted[group] {
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

func (m *MySQLHandler) Connect() {
	password, err := os.ReadFile(Cfg.Db.PasswordPath)
	if err != nil {
		Logger.Panic("Could not read db password", zap.Error(err))
	}
	cfg := mysql.Config{
		User:                 Cfg.Db.User,
		Passwd:               string(password),
		Net:                  "tcp",
		AllowNativePasswords: true,
		Addr:                 fmt.Sprintf("%s:%d", Cfg.Db.Host, Cfg.Db.Port),
		DBName:               Cfg.Db.DbName,
	}
	// Get a database handle.
	m.DB, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		Logger.Panic("Error opening DB connection", zap.Error(err))
	}
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
