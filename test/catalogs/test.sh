#!/bin/sh

set -e

echo "## Catalog regression tests"

if [ -n "$1" ]; then
    xmlcatalog=$1
else
    xmlcatalog=./xmlcatalog
fi

exitcode=0

for i in test/catalogs/*.script ; do
    name=$(basename $i .script)
    xml="./test/catalogs/$name.xml"

    if [ -f $xml ] ; then
        if [ ! -f result/catalogs/$name ] ; then
            echo New test file $name
            $xmlcatalog --shell $xml < $i 2>&1 > result/catalogs/$name
        else
            $xmlcatalog --shell $xml < $i 2>&1 > catalog.out
            log=$(diff result/catalogs/$name catalog.out)
            if [ -n "$log" ] ; then
                echo $name result
                echo "$log"
                exitcode=1
            fi
            rm catalog.out
        fi
    fi
done

for i in test/catalogs/*.script ; do
    name=$(basename $i .script)
    sgml="./test/catalogs/$name.sgml"

    if [ -f $sgml ] ; then
        if [ ! -f result/catalogs/$name ] ; then
            echo New test file $name
            $xmlcatalog --shell $sgml < $i > result/catalogs/$name
        else
            $xmlcatalog --shell $sgml < $i > catalog.out
            log=$(diff result/catalogs/$name catalog.out)
            if [ -n "$log" ] ; then
                echo $name result
                echo "$log"
                exitcode=1
            fi
            rm catalog.out
        fi
    fi
done

# Add and del operations on XML Catalogs

$xmlcatalog --create --noout mycatalog
$xmlcatalog --noout --add public Pubid sysid mycatalog
$xmlcatalog --noout --add public Pubid2 sysid2 mycatalog
$xmlcatalog --noout --add public Pubid3 sysid3 mycatalog
diff result/catalogs/mycatalog.full mycatalog
$xmlcatalog --noout --del sysid mycatalog
$xmlcatalog --noout --del sysid3 mycatalog
$xmlcatalog --noout --del sysid2 mycatalog
diff result/catalogs/mycatalog.empty mycatalog
rm -f mycatalog

exit $exitcode
