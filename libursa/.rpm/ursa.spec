%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: ursa
Summary: This is the shared crypto library for Hyperledger components.
Version: @@VERSION@@
Release: 1
License: MIT or ASL 2.0
Group: Applications/System
Source0: %{name}-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
