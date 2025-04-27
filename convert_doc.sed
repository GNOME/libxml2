# Delete function names
/^ \* (xml|xlink|html)[_[:alnum:]]+:/ d

# Escape
/^ \* /s/#/\\#/g

# Convert parameter names
/^ \* / s/@([_[:alnum:]]+)([^:_[:alnum:]]|$)/`\1`\2/g

# Convert parameters and return values
s/^ \* +@([_[:alnum:]]+):[  ]*/ * @param \1  /
s/^ \* +[Rr]eturns?[[:>:]]:?/ * @returns/

# Convert file headers
s/^ \* +Summary: *(.*)/ * @brief \1\n * /
s/^ \* +Description: */ * /
s/^ \* +Copy:/ * @copyright/
s/^ \* +Author:/ * @author/
s/^ \* +DEPRECATED:?/ * @deprecated/

# Convert ignored sections
s/DOC_DISABLE/@cond IGNORE/
s/DOC_ENABLE/@endcond/
