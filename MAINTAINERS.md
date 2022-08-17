# Making a release

## Rebuild generated files and documentation

The documentation and some generated files can be rebuilt by running

    make -C doc rebuild

This requires `xsltproc` to be installed.

## Update the NEWS file

You can get started by running

    git log --format='- %s (%an)' [previous-release-tag]..

## Bump the version number

Edit the version number in `configure.ac` if you haven't done so already.

## Build the tarball

I'd recommend to build the tarball by running

    make distcheck

which performs some useful checks as well.

## Upload the tarball

Follow the instructions at
<https://wiki.gnome.org/MaintainersCorner/Releasing>:

    scp libxml2-[version].tar.xz master.gnome.org:
    ssh master.gnome.org ftpadmin install libxml2-[version].tar.xz

## Tag the release

Create an annotated tag and push it:

    git tag -a [version] -m 'Release [version]'
    git push origin [version]

## Create a GitLab release

Create a new GitLab release on
<https://gitlab.gnome.org/GNOME/libxml2/-/releases>.

## Announce the release

Announce the release by sending an email to the mailing list at
xml@gnome.org.

