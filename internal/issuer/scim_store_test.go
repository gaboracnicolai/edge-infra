package issuer

import (
	"context"
	"errors"
	"testing"
)

// The SCIM store against real Postgres: a provisioned user has no password,
// is found by OIDC sign-in in any letter case, cannot be created twice, and
// deactivating it disables it.
func TestSCIMStoreProvisionsPasswordlessUser(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	u, err := s.CreateSCIMUser(ctx, SCIMUser{UserName: "Grace@Corp.example", DisplayName: "Grace", ExternalID: "ext-7", Active: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.UserName != "grace@corp.example" || !u.Active || u.ExternalID != "ext-7" {
		t.Fatalf("created %+v", u)
	}
	if _, err := s.CreateSCIMUser(ctx, SCIMUser{UserName: "GRACE@corp.example", Active: true}); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate create err = %v, want ErrUserExists", err)
	}

	l, err := s.GetLoginByEmail(ctx, "GRACE@CORP.EXAMPLE")
	if err != nil || l.ID != u.ID || l.Disabled || l.PasswordHash != "" {
		t.Fatalf("GetLoginByEmail = %+v, %v", l, err)
	}
	list, total, err := s.ListSCIMUsers(ctx, "userName", "grace@CORP.example", 0, 10)
	if err != nil || total != 1 || len(list) != 1 || list[0].ID != u.ID {
		t.Fatalf("filter userName = %v total %d err %v", list, total, err)
	}

	u.Active = false
	if _, err := s.ReplaceSCIMUser(ctx, u.ID, *u); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if l, _ := s.GetLoginByEmail(ctx, "grace@corp.example"); l == nil || !l.Disabled {
		t.Fatalf("after deactivate: %+v, want disabled", l)
	}

	if err := s.DeleteSCIMUser(ctx, u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetLoginByEmail(ctx, "grace@corp.example"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("after delete err = %v, want ErrUserNotFound", err)
	}
}
