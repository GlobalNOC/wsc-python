################################################################################
NAME = $(shell python3 -c "import tomllib; d=tomllib.load(open('pyproject.toml','rb')); print(d['project']['name'])")
VERSION = $(shell python3 -c "import tomllib; d=tomllib.load(open('pyproject.toml','rb')); print(d['project']['version'])")
RELEASE = $(shell rpmspec --srpm -q --qf '%{release}' $(NAME).spec)

APP_FULLNAME = $(NAME)-$(VERSION)
DIST_DIR = dist/$(APP_FULLNAME)
TARBALL = dist/$(APP_FULLNAME).tar.gz

# All files needed to build the RPM should be listed here
DIST_FILES = $(NAME).spec pyproject.toml README.md
DIST_DIRS = config src
################################################################################

.PHONY: all clean dist rpm

all: rpm

clean:
	rm -rf dist

dist: clean
	mkdir -p $(DIST_DIR)

	cp $(DIST_FILES) $(DIST_DIR)
	cp -a $(DIST_DIRS) $(DIST_DIR)

	uv build --wheel --out-dir $(DIST_DIR)
	tar czf $(TARBALL) --exclude='__pycache__' -C dist $(APP_FULLNAME)

rpm: dist
	rpmbuild -vv -tb $(TARBALL) \
		-D 'py_name $(NAME)' \
		-D 'py_version $(VERSION)' \
		-D '_topdir /rpmbuild'
	cp -f /rpmbuild/RPMS/**/*.rpm dist/
	if test -w "${GITHUB_ENV}"; then \
		echo "name=$(NAME)" >> $$GITHUB_ENV; \
		echo "version=$(VERSION)-$(RELEASE)" >> $$GITHUB_ENV; \
	fi
