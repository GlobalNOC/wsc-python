%global python3_pkgversion 3.11
%global venv /opt/grnoc/%{py_name}

################################################################################
# NOTE: YOU PROBABLY DO NOT NEED TO CHANGE THESE

%global py_pkg %(echo '%{py_name}' | sed -e 's/-/_/g')
%global python3_wheelname %{py_pkg}-%{py_version}-py3-none-any.whl

# summary/description text
# pull this from pyproject.toml
%global pkg_summary %(python3 -c "import tomllib; d=tomllib.load(open('pyproject.toml','rb')); print(d['project']['description'])")

# package release number (use 1 if unsure)
%global pkg_release 1

# disable RPM debug garbage
%global debug_package %{nil}

################################################################################
# NOTE: Unless you need to set BuildArch, these are probably fine as they are

Name:           python%{python3_pkgversion}-%{py_name}
Version:        %{py_version}
Release:        %{pkg_release}%{?dist}
Summary:        %{pkg_summary}

License:        Apache-2.0
URL:            https://github.com/GlobalNOC/wsc-python

# the location isn't used, but rpmlint complains if this isn't a URL
Source0:        https://github.grnoc.iu.edu/%{py_name}-%{version}.tar.gz

AutoReqProv:    no

BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  python%{python3_pkgversion}-rpm-macros

Requires:       python%{python3_pkgversion}

%description
%{pkg_summary}

%prep
%autosetup -n %{py_name}-%{py_version}

%build

%install
rm -rf %{buildroot}

# create venv and install wheel
uv venv --python /usr/bin/python3.11 %{buildroot}/%{venv}
uv pip install --python %{buildroot}%{venv}/bin/python3 %{python3_wheelname}

# fix venv path and remove unused files with buildroot path
uv tool run --from virtualenv-tools3 virtualenv-tools --update-path %{venv} %{buildroot}%{venv}
rm -f %{buildroot}%{venv}/bin/activate.{bat,nu}

# install the wsutil.py script to /usr/bin
install -D -m 0755 %{buildroot}%{venv}/bin/wsutil.py %{buildroot}%{_bindir}/wsutil.py

%files
%{_bindir}/*
%{venv}
