%define _build_id_links none

%ifarch x86_64
%define karch x86
%define asmarch x86
%endif

# whether to use LLVM-built kernel package dependencies
%define llvm_kbuild 0

Name: kernel-lqx
Summary: The Linux Kernel with Liquorix Patches

%define _basekver 6.8
%define _stablekver 9
Version: %{_basekver}.%{_stablekver}

%define flaver lqx1

Release:%{flaver}.0%{?dist}

%define rpmver %{version}-%{release}
%define krelstr %{release}.%{_arch}
%define kverstr %{version}-%{krelstr}

License: GPLv2 and Redistributable, no modifications permitted
Group: System Environment/Kernel
Vendor: The Linux Community and Liquorix Maintainers
URL: https://www.liquorix.net
Source0: kernel-%{version}_%{flaver}.tar.gz
%define __spec_install_post /usr/lib/rpm/brp-compress || :
%define debug_package %{nil}
Source2: rnread-%{name}
BuildRequires: python3-devel make perl-generators perl-interpreter openssl-devel bison flex findutils git-core perl-devel openssl elfutils-devel gawk binutils m4 tar hostname bzip2 bash gzip xz bc diffutils redhat-rpm-config net-tools elfutils patch rpm-build dwarves kmod libkcapi-hmaccalc perl-Carp rsync grubby pesign
%if %{llvm_kbuild}
BuildRequires: llvm%{_isa} lld%{_isa} clang%{_isa}
%else
BuildRequires: gcc%{_isa}
%endif
Requires: %{name}-core-%{rpmver} = %{kverstr}, %{name}-modules-%{rpmver} = %{kverstr}
Provides: rnread-%{name} = 1
Provides: %{name}%{_basekver} = %{rpmver}

%description
The kernel-%{flaver} meta package

%package core
Summary: Kernel core package
Group: System Environment/Kernel
Provides: Provides: installonlypkg(kernel), kernel = %{rpmver}, kernel-core = %{rpmver}, kernel-core-uname-r = %{kverstr}, kernel-uname-r = %{kverstr}, kernel-%{_arch} = %{rpmver}, kernel-core%{_isa} = %{rpmver}, kernel-core-%{rpmver} = %{kverstr}, %{name}-core-%{rpmver} = %{kverstr}, kernel-drm-nouveau = 16
Provides: %{name}%{_basekver}-core = %{rpmver}
Requires: bash, coreutils, dracut, linux-firmware, /usr/bin/kernel-install, kernel-modules-%{rpmver} = %{kverstr}
Supplements: %{name} = %{rpmver}
%description core
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

%package modules
Summary: Kernel modules to match the core kernel
Group: System Environment/Kernel
Provides: installonlypkg(kernel-module), kernel-modules = %{rpmver}, kernel-modules%{_isa} = %{rpmver}, kernel-modules-uname-r = %{kverstr}, kernel-modules-%{_arch} = %{rpmver}, kernel-modules-%{rpmver} = %{kverstr}, %{name}-modules-%{rpmver} = %{kverstr}
Provides: %{name}%{_basekver}-modules = %{rpmver}
Supplements: %{name} = %{rpmver}
%description modules
This package provides kernel modules for the core kernel package.

%package headers
Summary: Header files for the Linux kernel for use by glibc
Group: Development/System
Provides: kernel-headers = %{kverstr}, glibc-kernheaders = 3.0-46, kernel-headers%{_isa} = %{kverstr}
Obsoletes: kernel-headers < %{kverstr}, glibc-kernheaders < 3.0-46
%description headers
Kernel-headers includes the C header files that specify the interface
between the Linux kernel and userspace libraries and programs.  The
header files define structures and constants that are needed for
building most standard programs and are also needed for rebuilding the
glibc package.

%package devel
Summary: Development package for building kernel modules to match the %{kverstr} kernel
Group: System Environment/Kernel
AutoReqProv: no
Requires: findutils perl-interpreter openssl-devel flex make bison elfutils-libelf-devel
%if %{llvm_kbuild}
Requires: llvm%{_isa} lld%{_isa} clang%{_isa}
%else
Requires: gcc%{_isa}
%endif
Enhances: dkms akmods
Provides: installonlypkg(kernel), kernel-devel = %{rpmver}, kernel-devel-uname-r = %{kverstr}, kernel-devel-%{_arch} = %{rpmver}, kernel-devel%{_isa} = %{rpmver}, kernel-devel-%{rpmver} = %{kverstr}, %{name}-devel-%{rpmver} = %{kverstr}
Provides: %{name}%{_basekver}-devel = %{rpmver}
%description -n %{name}-devel
This package provides kernel headers and makefiles sufficient to build modules
against the %{kverstr} kernel package.

%prep
%setup -q -n kernel-%{version}_%{flaver}

%build
make %{?_smp_mflags} EXTRAVERSION=-%{krelstr}
gcc ./scripts/sign-file.c -o ./scripts/sign-file -lssl -lcrypto

%install

ImageName=$(make image_name | tail -n 1)

mkdir -p %{buildroot}/boot

cp -v $ImageName %{buildroot}/boot/vmlinuz-%{kverstr}
chmod 755 %{buildroot}/boot/vmlinuz-%{kverstr}

make %{?_smp_mflags} INSTALL_MOD_PATH=%{buildroot} modules_install
make %{?_smp_mflags} INSTALL_HDR_PATH=%{buildroot}/usr headers_install

cp -v System.map %{buildroot}/boot/System.map-%{kverstr}
cp -v .config %{buildroot}/boot/config-%{kverstr}
bzip2 -9 --keep vmlinux
mv vmlinux.bz2 %{buildroot}/boot/vmlinux-%{kverstr}

# prepare -devel files
### all of the things here are derived from the Fedora kernel.spec
### see 
##### https://src.fedoraproject.org/rpms/kernel/blob/rawhide/f/kernel.spec
rm -f %{buildroot}/lib/modules/%{kverstr}/build
rm -f %{buildroot}/lib/modules/%{kverstr}/source
mkdir -p %{buildroot}/lib/modules/%{kverstr}/build
(cd %{buildroot}/lib/modules/%{kverstr} ; ln -s build source)
# dirs for additional modules per module-init-tools, kbuild/modules.txt
mkdir -p %{buildroot}/lib/modules/%{kverstr}/updates
mkdir -p %{buildroot}/lib/modules/%{kverstr}/weak-updates
# CONFIG_KERNEL_HEADER_TEST generates some extra files in the process of
# testing so just delete
find . -name *.h.s -delete
# first copy everything
cp --parents `find  -type f -name "Makefile*" -o -name "Kconfig*"` %{buildroot}/lib/modules/%{kverstr}/build
if [ ! -e Module.symvers ]; then
touch Module.symvers
fi
cp Module.symvers %{buildroot}/lib/modules/%{kverstr}/build
cp System.map %{buildroot}/lib/modules/%{kverstr}/build
if [ -s Module.markers ]; then
  cp Module.markers %{buildroot}/lib/modules/%{kverstr}/build
fi
 
# create the kABI metadata for use in packaging
# NOTENOTE: the name symvers is used by the rpm backend
# NOTENOTE: to discover and run the /usr/lib/rpm/fileattrs/kabi.attr
# NOTENOTE: script which dynamically adds exported kernel symbol
# NOTENOTE: checksums to the rpm metadata provides list.
# NOTENOTE: if you change the symvers name, update the backend too
echo "**** GENERATING kernel ABI metadata ****"
gzip -c9 < Module.symvers > %{buildroot}/boot/symvers-%{kverstr}.gz
cp %{buildroot}/boot/symvers-%{kverstr}.gz %{buildroot}/lib/modules/%{kverstr}/symvers.gz

# then drop all but the needed Makefiles/Kconfig files
rm -rf %{buildroot}/lib/modules/%{kverstr}/build/scripts
rm -rf %{buildroot}/lib/modules/%{kverstr}/build/include
cp .config %{buildroot}/lib/modules/%{kverstr}/build
cp -a scripts %{buildroot}/lib/modules/%{kverstr}/build
rm -rf %{buildroot}/lib/modules/%{kverstr}/build/scripts/tracing
rm -f %{buildroot}/lib/modules/%{kverstr}/build/scripts/spdxcheck.py
 
# Files for 'make scripts' to succeed with kernel-devel.
mkdir -p %{buildroot}/lib/modules/%{kverstr}/build/security/selinux/include
cp -a --parents security/selinux/include/classmap.h %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents security/selinux/include/initial_sid_to_string.h %{buildroot}/lib/modules/%{kverstr}/build
mkdir -p %{buildroot}/lib/modules/%{kverstr}/build/tools/include/tools
cp -a --parents tools/include/tools/be_byteshift.h %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/include/tools/le_byteshift.h %{buildroot}/lib/modules/%{kverstr}/build
 
# Files for 'make prepare' to succeed with kernel-devel.
cp -a --parents tools/include/linux/compiler* %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/include/linux/types.h %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/build/Build.include %{buildroot}/lib/modules/%{kverstr}/build
cp --parents tools/build/Build %{buildroot}/lib/modules/%{kverstr}/build
cp --parents tools/build/fixdep.c %{buildroot}/lib/modules/%{kverstr}/build
cp --parents tools/objtool/sync-check.sh %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/bpf/resolve_btfids %{buildroot}/lib/modules/%{kverstr}/build
 
cp --parents security/selinux/include/policycap_names.h %{buildroot}/lib/modules/%{kverstr}/build
cp --parents security/selinux/include/policycap.h %{buildroot}/lib/modules/%{kverstr}/build
 
cp -a --parents tools/include/asm-generic %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/include/linux %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/include/uapi/asm %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/include/uapi/asm-generic %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/include/uapi/linux %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/include/vdso %{buildroot}/lib/modules/%{kverstr}/build
cp --parents tools/scripts/utilities.mak %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/lib/subcmd %{buildroot}/lib/modules/%{kverstr}/build
cp --parents tools/lib/*.c %{buildroot}/lib/modules/%{kverstr}/build
cp --parents tools/objtool/*.[ch] %{buildroot}/lib/modules/%{kverstr}/build
cp --parents tools/objtool/Build %{buildroot}/lib/modules/%{kverstr}/build
cp --parents tools/objtool/include/objtool/*.h %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/lib/bpf %{buildroot}/lib/modules/%{kverstr}/build
cp --parents tools/lib/bpf/Build %{buildroot}/lib/modules/%{kverstr}/build
 
if [ -f tools/objtool/objtool ]; then
  cp -a tools/objtool/objtool %{buildroot}/lib/modules/%{kverstr}/build/tools/objtool/ || :
fi
if [ -f tools/objtool/fixdep ]; then
  cp -a tools/objtool/fixdep %{buildroot}/lib/modules/%{kverstr}/build/tools/objtool/ || :
fi
if [ -d arch/%{karch}/scripts ]; then
  cp -a arch/%{karch}/scripts %{buildroot}/lib/modules/%{kverstr}/build/arch/%{_arch} || :
fi
if [ -f arch/%{karch}/*lds ]; then
  cp -a arch/%{karch}/*lds %{buildroot}/lib/modules/%{kverstr}/build/arch/%{_arch}/ || :
fi
if [ -f arch/%{asmarch}/kernel/module.lds ]; then
  cp -a --parents arch/%{asmarch}/kernel/module.lds %{buildroot}/lib/modules/%{kverstr}/build/
fi
find %{buildroot}/lib/modules/%{kverstr}/build/scripts \( -iname "*.o" -o -iname "*.cmd" \) -exec rm -f {} +
%ifarch ppc64le
cp -a --parents arch/powerpc/lib/crtsavres.[So] %{buildroot}/lib/modules/%{kverstr}/build/
%endif
if [ -d arch/%{asmarch}/include ]; then
  cp -a --parents arch/%{asmarch}/include %{buildroot}/lib/modules/%{kverstr}/build/
fi
%ifarch aarch64
# arch/arm64/include/asm/xen references arch/arm
cp -a --parents arch/arm/include/asm/xen %{buildroot}/lib/modules/%{kverstr}/build/
# arch/arm64/include/asm/opcodes.h references arch/arm
cp -a --parents arch/arm/include/asm/opcodes.h %{buildroot}/lib/modules/%{kverstr}/build/
%endif
# include the machine specific headers for ARM variants, if available.
%ifarch %{arm}
if [ -d arch/%{asmarch}/mach-${Variant}/include ]; then
  cp -a --parents arch/%{asmarch}/mach-${Variant}/include %{buildroot}/lib/modules/%{kverstr}/build/
fi
# include a few files for 'make prepare'
cp -a --parents arch/arm/tools/gen-mach-types %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/arm/tools/mach-types %{buildroot}/lib/modules/%{kverstr}/build/
 
%endif
cp -a include %{buildroot}/lib/modules/%{kverstr}/build/include
%ifarch i686 x86_64
# files for 'make prepare' to succeed with kernel-devel
cp -a --parents arch/x86/entry/syscalls/syscall_32.tbl %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/entry/syscalls/syscall_64.tbl %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/tools/relocs_32.c %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/tools/relocs_64.c %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/tools/relocs.c %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/tools/relocs_common.c %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/tools/relocs.h %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/purgatory/purgatory.c %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/purgatory/stack.S %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/purgatory/setup-x86_64.S %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/purgatory/entry64.S %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/boot/string.h %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/boot/string.c %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents arch/x86/boot/ctype.h %{buildroot}/lib/modules/%{kverstr}/build/
 
cp -a --parents scripts/syscalltbl.sh %{buildroot}/lib/modules/%{kverstr}/build/
cp -a --parents scripts/syscallhdr.sh %{buildroot}/lib/modules/%{kverstr}/build/
 
cp -a --parents tools/arch/x86/include/asm %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/arch/x86/include/uapi/asm %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/objtool/arch/x86/lib %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/arch/x86/lib/ %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/arch/x86/tools/gen-insn-attr-x86.awk %{buildroot}/lib/modules/%{kverstr}/build
cp -a --parents tools/objtool/arch/x86/ %{buildroot}/lib/modules/%{kverstr}/build
 
%endif
# Clean up intermediate tools files
find %{buildroot}/lib/modules/%{kverstr}/build/tools \( -iname "*.o" -o -iname "*.cmd" \) -exec rm -f {} +
 
# Make sure the Makefile and version.h have a matching timestamp so that
# external modules can be built
touch -r %{buildroot}/lib/modules/%{kverstr}/build/Makefile %{buildroot}/lib/modules/%{kverstr}/build/include/generated/uapi/linux/version.h
 
# Copy .config to include/config/auto.conf so "make prepare" is unnecessary.
cp %{buildroot}/lib/modules/%{kverstr}/build/.config %{buildroot}/lib/modules/%{kverstr}/build/include/config/auto.conf

find %{buildroot}/lib/modules/%{kverstr} -name "*.ko" -type f >modnames
 
# mark modules executable so that strip-to-file can strip them
xargs --no-run-if-empty chmod u+x < modnames
 
# Generate a list of modules for block and networking.
 
grep -F /drivers/ modnames | xargs --no-run-if-empty nm -upA |
sed -n 's,^.*/\([^/]*\.ko\):  *U \(.*\)$,\1 \2,p' > drivers.undef
 
collect_modules_list()
{
  sed -r -n -e "s/^([^ ]+) \\.?($2)\$/\\1/p" drivers.undef |
LC_ALL=C sort -u > %{buildroot}/lib/modules/%{kverstr}/modules.$1
  if [ ! -z "$3" ]; then
sed -r -e "/^($3)\$/d" -i %{buildroot}/lib/modules/%{kverstr}/modules.$1
  fi
}
 
collect_modules_list networking \
  'register_netdev|ieee80211_register_hw|usbnet_probe|phy_driver_register|rt(l_|2x00)(pci|usb)_probe|register_netdevice'
collect_modules_list block \
  'ata_scsi_ioctl|scsi_add_host|scsi_add_host_with_dma|blk_alloc_queue|blk_init_queue|register_mtd_blktrans|scsi_esp_register|scsi_register_device_handler|blk_queue_physical_block_size' 'pktcdvd.ko|dm-mod.ko'
collect_modules_list drm \
  'drm_open|drm_init'
collect_modules_list modesetting \
  'drm_crtc_init'
 
# detect missing or incorrect license tags
( find %{buildroot}/lib/modules/%{kverstr} -name '*.ko' | xargs /sbin/modinfo -l | \
grep -E -v 'GPL( v2)?$|Dual BSD/GPL$|Dual MPL/GPL$|GPL and additional rights$' ) && exit 1
 
remove_depmod_files()
{
# remove files that will be auto generated by depmod at rpm -i time
pushd %{buildroot}/lib/modules/%{kverstr}/
rm -f modules.{alias,alias.bin,builtin.alias.bin,builtin.bin} \
  modules.{dep,dep.bin,devname,softdep,symbols,symbols.bin}
popd
}
 
remove_depmod_files
	
	
mkdir -p %{buildroot}%{_prefix}/src/kernels
mv %{buildroot}/lib/modules/%{kverstr}/build %{buildroot}%{_prefix}/src/kernels/%{kverstr}
 
# This is going to create a broken link during the build, but we don't use
# it after this point.  We need the link to actually point to something
# when kernel-devel is installed, and a relative link doesn't work across
# the F17 UsrMove feature.
ln -sf %{_prefix}/src/kernels/%{kverstr} %{buildroot}/lib/modules/%{kverstr}/build	
	
find %{buildroot}%{_prefix}/src/kernels -name ".*.cmd" -delete
#

cp -v  %{buildroot}/boot/vmlinuz-%{kverstr} %{buildroot}/lib/modules/%{kverstr}/vmlinuz
mkdir -p %{buildroot}/%{_bindir}
cp -v  %{SOURCE2} %{buildroot}/%{_bindir}/rnread-%{name}
chmod u+rwx,go+rx %{buildroot}/%{_bindir}/rnread-%{name}

%clean
rm -rf %{buildroot}

%post core
if [ `uname -i` == "x86_64" -o `uname -i` == "i386" ] &&
   [ -f /etc/sysconfig/kernel ]; then
  /bin/sed -r -i -e 's/^DEFAULTKERNEL=kernel-smp$/DEFAULTKERNEL=kernel/' /etc/sysconfig/kernel || exit $?
fi

%posttrans core
/bin/kernel-install add %{kverstr} /lib/modules/%{kverstr}/vmlinuz || exit $?

### Donation plug
printf "\n\n\n  This package "
printf '%{name}'
printf " is being worked by me as a hobby in my free time\n"
echo -e "  If you're interested in supporting me doing this, you can go to:\n"
echo -e "\t\thttps://liberapay.com/rmnscnce/donate\n\n  And donate so I can keep this package maintained for everyone\n\nYou can read news and announcements for this software using "'rnread-%{name}\n\n\n'

%preun core
/bin/kernel-install remove %{kverstr} /lib/modules/%{kverstr}/vmlinuz || exit $?
if [ -x /usr/sbin/weak-modules ]
then
    /usr/sbin/weak-modules --remove-kernel %{kverstr} || exit $?
fi

%post devel
if [ -f /etc/sysconfig/kernel ]
then
    . /etc/sysconfig/kernel || exit $?
fi
if [ "$HARDLINK" != "no" -a -x /usr/bin/hardlink -a ! -e /run/ostree-booted ] 
then
    (cd /usr/src/kernels/%{kverstr} &&
     /usr/bin/find . -type f | while read f; do
       hardlink -c /usr/src/kernels/*%{?dist}.*/$f $f 2>&1 >/dev/null
     done)
fi

%post modules
/sbin/depmod -a %{kverstr}

%postun modules
/sbin/depmod -a %{kverstr}

%files core
%defattr (-, root, root)
%exclude /%{kverstr}
/boot/*
%exclude /boot/vmlinux-%{kverstr}
/lib/modules/%{kverstr}/vmlinuz
/lib/modules/%{kverstr}/symvers.gz

%files modules
%defattr (-, root, root)
/lib/modules/%{kverstr}
%exclude /lib/modules/%{kverstr}/vmlinuz
%exclude /lib/modules/%{kverstr}/symvers.gz
%exclude /lib/modules/%{kverstr}/build
%exclude /lib/modules/%{kverstr}/source

%files headers
%defattr (-, root, root)
/usr/include

%files devel
%defattr (-, root, root)
/usr/src/kernels/%{kverstr}
/lib/modules/%{kverstr}/build
/lib/modules/%{kverstr}/source

%files
%defattr (-, root, root)
%attr(0755, root, root) %{_bindir}/rnread-%{name}
