
html_files = files(
    'general.html',
    'index.html',
)

html_modules = files(
    'libxml2-HTMLparser.html',
    'libxml2-HTMLtree.html',
    'libxml2-SAX.html',
    'libxml2-SAX2.html',
    'libxml2-c14n.html',
    'libxml2-catalog.html',
    'libxml2-chvalid.html',
    'libxml2-debugXML.html',
    'libxml2-dict.html',
    'libxml2-encoding.html',
    'libxml2-entities.html',
    'libxml2-globals.html',
    'libxml2-hash.html',
    'libxml2-list.html',
    'libxml2-nanoftp.html',
    'libxml2-nanohttp.html',
    'libxml2-parser.html',
    'libxml2-parserInternals.html',
    'libxml2-pattern.html',
    'libxml2-relaxng.html',
    'libxml2-schemasInternals.html',
    'libxml2-schematron.html',
    'libxml2-threads.html',
    'libxml2-tree.html',
    'libxml2-uri.html',
    'libxml2-valid.html',
    'libxml2-xinclude.html',
    'libxml2-xlink.html',
    'libxml2-xmlIO.html',
    'libxml2-xmlautomata.html',
    'libxml2-xmlerror.html',
    'libxml2-xmlexports.html',
    'libxml2-xmlmemory.html',
    'libxml2-xmlmodule.html',
    'libxml2-xmlreader.html',
    'libxml2-xmlregexp.html',
    'libxml2-xmlsave.html',
    'libxml2-xmlschemas.html',
    'libxml2-xmlschemastypes.html',
    'libxml2-xmlstring.html',
    'libxml2-xmlunicode.html',
    'libxml2-xmlversion.html',
    'libxml2-xmlwriter.html',
    'libxml2-xpath.html',
    'libxml2-xpathInternals.html',
    'libxml2-xpointer.html',
    'libxml2.devhelp2',
)

extra_files = files('home.png', 'left.png', 'right.png', 'style.css', 'up.png')

devhelp = [html_files, html_modules, extra_files]

install_data(devhelp, install_dir: dir_data / 'gtk-doc' / 'html' / 'libxml2')
