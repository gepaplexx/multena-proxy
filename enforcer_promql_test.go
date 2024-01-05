package main

import (
	"strings"
	"testing"
)

func Test_promqlEnforcer(t *testing.T) {
	type args struct {
		query        string
		tenantLabels map[string]bool
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "case 1",
			args: args{
				query:        "up",
				tenantLabels: map[string]bool{"namespace1": true},
			},
			want:    "up{namespace=\"namespace1\"}",
			wantErr: false,
		},
		{
			name: "case 2",
			args: args{
				query:        "{__name__=\"up\",namespace=\"namespace2\"}",
				tenantLabels: map[string]bool{"namespace1": true},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "case 3",
			args: args{
				query:        "up{namespace=\"namespace1\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true},
			},
			want:    "up{namespace=\"namespace1\"}",
			wantErr: false,
		},
		{
			name: "case 4",
			args: args{
				query:        "up",
				tenantLabels: map[string]bool{"namespace": true, "grrr": true},
			},
			want:    "up{namespace=~\"namespace|grrr\"}|s|up{namespace=~\"grrr|namespace\"}",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PromQLEnforcer{}.Enforce(tt.args.query, tt.args.tenantLabels, "namespace")
			if (err != nil) != tt.wantErr {
				t.Errorf("promqlEnforcer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != strings.Split(tt.want, "|s|")[0] && got != strings.Split(tt.want, "|s|")[1] {
				t.Errorf("promqlEnforcer() = %v, want %v", got, tt.want)
			}
		})
	}
}
