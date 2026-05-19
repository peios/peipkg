package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// InsertPackage records a newly-installed package. It fails if a
// package with the same name is already recorded; an upgrade is a
// [queries.DeletePackage] of the old followed by an InsertPackage of the
// new, within one [DB.Tx].
func (x *queries) InsertPackage(ctx context.Context, p Package) error {
	_, err := x.q.ExecContext(ctx,
		`INSERT INTO package
		   (name, version, architecture, origin_repo, installed_at, manifest)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		p.Name, p.Version, p.Architecture, nullString(p.OriginRepo),
		p.InstalledAt.Unix(), p.Manifest)
	if err != nil {
		return fmt.Errorf("peipkg/db: insert package %q: %w", p.Name, err)
	}
	return nil
}

// GetPackage returns the installed package of the given name. found is
// false if no such package is installed.
func (x *queries) GetPackage(ctx context.Context, name string) (pkg Package, found bool, err error) {
	row := x.q.QueryRowContext(ctx,
		`SELECT name, version, architecture, origin_repo, installed_at, manifest
		 FROM package WHERE name = ?`, name)
	pkg, err = scanPackage(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Package{}, false, nil
	}
	if err != nil {
		return Package{}, false, fmt.Errorf("peipkg/db: get package %q: %w", name, err)
	}
	return pkg, true, nil
}

// ListPackages returns every installed package, ordered by name.
func (x *queries) ListPackages(ctx context.Context) ([]Package, error) {
	rows, err := x.q.QueryContext(ctx,
		`SELECT name, version, architecture, origin_repo, installed_at, manifest
		 FROM package ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: list packages: %w", err)
	}
	defer rows.Close()

	var packages []Package
	for rows.Next() {
		pkg, err := scanPackage(rows)
		if err != nil {
			return nil, fmt.Errorf("peipkg/db: list packages: %w", err)
		}
		packages = append(packages, pkg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("peipkg/db: list packages: %w", err)
	}
	return packages, nil
}

// DeletePackage removes a package and, by cascade, all of its
// package_file rows. Deleting a package that is not installed is not an
// error.
func (x *queries) DeletePackage(ctx context.Context, name string) error {
	if _, err := x.q.ExecContext(ctx, "DELETE FROM package WHERE name = ?", name); err != nil {
		return fmt.Errorf("peipkg/db: delete package %q: %w", name, err)
	}
	return nil
}

// InsertPackageFiles records the filesystem objects a package owns. It
// fails — and, inside a [DB.Tx], rolls the transaction back — if any
// non-directory path is already owned by another package, the
// collision rule enforced by the database.
func (x *queries) InsertPackageFiles(ctx context.Context, files []PackageFile) error {
	if len(files) == 0 {
		return nil
	}
	stmt, err := x.q.PrepareContext(ctx,
		`INSERT INTO package_file (package_name, path, type, hash, symlink_target)
		 VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("peipkg/db: prepare package-file insert: %w", err)
	}
	defer stmt.Close()

	for _, f := range files {
		_, err := stmt.ExecContext(ctx, f.PackageName, f.Path, string(f.Type),
			nullString(f.Hash), nullString(f.SymlinkTarget))
		if err != nil {
			return fmt.Errorf("peipkg/db: insert package file %q (package %q): %w",
				f.Path, f.PackageName, err)
		}
	}
	return nil
}

// PackageFiles returns every filesystem object owned by a package,
// ordered by path.
func (x *queries) PackageFiles(ctx context.Context, packageName string) ([]PackageFile, error) {
	rows, err := x.q.QueryContext(ctx,
		`SELECT package_name, path, type, hash, symlink_target
		 FROM package_file WHERE package_name = ? ORDER BY path`, packageName)
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: list files of package %q: %w", packageName, err)
	}
	defer rows.Close()
	return scanPackageFiles(rows, fmt.Sprintf("list files of package %q", packageName))
}

// FileOwners returns every package_file row registered at path. A
// non-directory path has at most one owner (the database enforces it);
// a directory may be shared by many packages.
func (x *queries) FileOwners(ctx context.Context, path string) ([]PackageFile, error) {
	rows, err := x.q.QueryContext(ctx,
		`SELECT package_name, path, type, hash, symlink_target
		 FROM package_file WHERE path = ? ORDER BY package_name`, path)
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: find owners of %q: %w", path, err)
	}
	defer rows.Close()
	return scanPackageFiles(rows, fmt.Sprintf("find owners of %q", path))
}

// scanPackage reads one package row.
func scanPackage(s scanner) (Package, error) {
	var (
		pkg         Package
		originRepo  sql.NullString
		installedAt int64
	)
	if err := s.Scan(&pkg.Name, &pkg.Version, &pkg.Architecture,
		&originRepo, &installedAt, &pkg.Manifest); err != nil {
		return Package{}, err
	}
	pkg.OriginRepo = originRepo.String // "" when NULL
	pkg.InstalledAt = time.Unix(installedAt, 0)
	return pkg, nil
}

// scanPackageFiles drains a package_file result set. context labels the
// wrapped error.
func scanPackageFiles(rows *sql.Rows, context string) ([]PackageFile, error) {
	var files []PackageFile
	for rows.Next() {
		var (
			f             PackageFile
			fileType      string
			hash          sql.NullString
			symlinkTarget sql.NullString
		)
		if err := rows.Scan(&f.PackageName, &f.Path, &fileType, &hash, &symlinkTarget); err != nil {
			return nil, fmt.Errorf("peipkg/db: %s: %w", context, err)
		}
		f.Type = FileType(fileType)
		f.Hash = hash.String                   // "" when NULL
		f.SymlinkTarget = symlinkTarget.String // "" when NULL
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("peipkg/db: %s: %w", context, err)
	}
	return files, nil
}
