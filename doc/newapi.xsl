<?xml version="1.0"?>
<!--
  Stylesheet to generate the HTML documentation from an XML API descriptions:
  xsltproc newapi.xsl libxml2-api.xml

  Daniel Veillard
-->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  extension-element-prefixes="exsl"
  exclude-result-prefixes="exsl">

  <!-- Import the resto of the site stylesheets -->
  <xsl:import href="site.xsl"/>

  <!-- Generate XHTML-1.0 transitional -->
  <xsl:output method="xml" encoding="ISO-8859-1" indent="yes"
      doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN"
      doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"/>

  <!-- Build keys for all symbols -->
  <xsl:key name="symbols" match="/api/symbols/*" use="@name"/>

  <!-- the target directory -->
  <xsl:variable name="htmldir">newhtml</xsl:variable>

  <xsl:template name="dumptext">
    <xsl:param name="text"/>
    <xsl:value-of select="$text"/>
  </xsl:template>

  <xsl:template match="macro" mode="toc">
    <xsl:text>#define </xsl:text><a href="#{@name}"><xsl:value-of select="@name"/></a><xsl:text>

</xsl:text>
  </xsl:template>

  <xsl:template match="struct" mode="toc">
    <xsl:text>Structure </xsl:text><a name="{@name}"><xsl:value-of select="@name"/></a><br/>
    <xsl:value-of select="@type"/><xsl:text> {
</xsl:text>
    <xsl:for-each select="field">
        <xsl:text>    </xsl:text>
	<xsl:value-of select="@type"/><xsl:text>&#9;</xsl:text>
	<xsl:value-of select="@name"/><xsl:text>&#9;: </xsl:text>
	<xsl:value-of select="substring(@info, 1, 50)"/><xsl:text>
</xsl:text>
    </xsl:for-each>
    <xsl:text>}

</xsl:text>
  </xsl:template>

  <xsl:template match="macro">
    <xsl:variable name="name" select="string(@name)"/>
    <h3><a name="{$name}"></a>Macro: <xsl:value-of select="$name"/></h3>
    <pre><xsl:text>#define </xsl:text><xsl:value-of select="$name"/></pre>
    <p>
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="info"/>
    </xsl:call-template>
    </p><xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="function" mode="toc">
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="return/@type"/>
    </xsl:call-template>
    <xsl:text>&#9;</xsl:text>
    <a href="#{@name}"><xsl:value-of select="@name"/></a>
    <xsl:text>&#9;(</xsl:text>
    <xsl:for-each select="arg">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="@type"/>
      </xsl:call-template>
      <xsl:text> </xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:if test="position() != last()">
        <xsl:text>, </xsl:text><br/><xsl:text>&#9;&#9;&#9;&#9;</xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>)</xsl:text><br/>
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="function">
    <xsl:variable name="name" select="string(@name)"/>
    <h3><a name="{$name}"></a>Function: <xsl:value-of select="$name"/></h3>
    <pre class="programlisting">
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="return/@type"/>
    </xsl:call-template>
    <xsl:text>&#9;</xsl:text>
    <xsl:value-of select="@name"/>
    <xsl:text>&#9;(</xsl:text>
    <xsl:for-each select="arg">
      <xsl:call-template name="dumptext">
        <xsl:with-param name="text" select="@type"/>
      </xsl:call-template>
      <xsl:text> </xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:if test="position() != last()">
        <xsl:text>, </xsl:text><br/><xsl:text>&#9;&#9;&#9;&#9;</xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>)</xsl:text><br/>
    <xsl:text>
</xsl:text>
    </pre>
    <p>
    <xsl:call-template name="dumptext">
      <xsl:with-param name="text" select="info"/>
    </xsl:call-template>
    </p><xsl:text>
</xsl:text>
    <div class="variablelist"><table border="0"><col align="left"/><tbody>
    <xsl:for-each select="arg">
      <tr>
        <td><span class="term"><i><tt><xsl:value-of select="@name"/></tt></i>:</span></td>
	<td><xsl:value-of select="@info"/></td>
      </tr>
    </xsl:for-each>
    <xsl:if test="return/@info">
      <tr>
        <td><span class="term"><i><tt>Returns</tt></i>:</span></td>
	<td><xsl:value-of select="return/@info"/></td>
      </tr>
    </xsl:if>
    </tbody></table></div>
  </xsl:template>

  <xsl:template match="exports" mode="toc">
    <xsl:apply-templates select="key('symbols', string(@symbol))" mode="toc"/>
  </xsl:template>

  <xsl:template match="exports">
    <xsl:apply-templates select="key('symbols', string(@symbol))"/>
  </xsl:template>

  <xsl:template match="file">
    <xsl:variable name="name" select="@name"/>
    <xsl:variable name="title">Module <xsl:value-of select="$name"/> from <xsl:value-of select="/api/@name"/></xsl:variable>
    <xsl:document href="{$htmldir}/libxml-{$name}.html" method="xml" encoding="ISO-8859-1"
      doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN"
      doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
	<html>
	  <head>
	    <xsl:call-template name="style"/>
	    <title><xsl:value-of select="$title"/></title>
	  </head>
	  <body bgcolor="#8b7765" text="#000000" link="#000000" vlink="#000000">
	    <xsl:call-template name="titlebox">
	      <xsl:with-param name="title" select="$title"/>
	    </xsl:call-template>
	  <table border="0" cellpadding="4" cellspacing="0" width="100%" align="center">
	    <tr>
	      <td bgcolor="#8b7765">
		<table border="0" cellspacing="0" cellpadding="2" width="100%">
		  <tr>
		    <td valign="top" width="200" bgcolor="#8b7765">
		      <xsl:call-template name="toc"/>
		    </td>
		    <td valign="top" bgcolor="#8b7765">
		      <table border="0" cellspacing="0" cellpadding="1" width="100%">
			<tr>
			  <td>
			    <table border="0" cellspacing="0" cellpadding="1" width="100%" bgcolor="#000000">
			      <tr>
				<td>
				  <table border="0" cellpadding="3" cellspacing="1" width="100%">
				    <tr>
				      <td bgcolor="#fffacd">
	    <h2>Table of Contents</h2>
	    <pre>
	    <xsl:apply-templates select="exports" mode="toc"/>
	    </pre>
	    <h2>Description</h2>
	    <xsl:text>
</xsl:text>
	    <xsl:apply-templates select="exports"/>
					<p><a href="bugs.html">Daniel Veillard</a></p>
				      </td>
				    </tr>
				  </table>
				</td>
			      </tr>
			    </table>
			  </td>
			</tr>
		      </table>
		    </td>
		  </tr>
		</table>
	      </td>
	    </tr>
	  </table>
	  </body>
	</html>
    </xsl:document>
  </xsl:template>

  <xsl:template match="file" mode="toc">
    <xsl:variable name="name" select="@name"/>
    <li> <a href="libxml-{$name}.html"><xsl:value-of select="$name"/></a></li>
  </xsl:template>

  <xsl:template match="/">
    <xsl:variable name="title">Reference Manual for <xsl:value-of select="/api/@name"/></xsl:variable>
    <xsl:document href="{$htmldir}/index.html" method="xml" encoding="ISO-8859-1"
      doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN"
      doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
	<html>
	  <head>
	    <xsl:call-template name="style"/>
	    <title><xsl:value-of select="$title"/></title>
	  </head>
	  <body bgcolor="#8b7765" text="#000000" link="#000000" vlink="#000000">
	    <xsl:call-template name="titlebox">
	      <xsl:with-param name="title" select="$title"/>
	    </xsl:call-template>
	  <table border="0" cellpadding="4" cellspacing="0" width="100%" align="center">
	    <tr>
	      <td bgcolor="#8b7765">
		<table border="0" cellspacing="0" cellpadding="2" width="100%">
		  <tr>
		    <td valign="top" width="200" bgcolor="#8b7765">
		      <xsl:call-template name="toc"/>
		    </td>
		    <td valign="top" bgcolor="#8b7765">
		      <table border="0" cellspacing="0" cellpadding="1" width="100%">
			<tr>
			  <td>
			    <table border="0" cellspacing="0" cellpadding="1" width="100%" bgcolor="#000000">
			      <tr>
				<td>
				  <table border="0" cellpadding="3" cellspacing="1" width="100%">
				    <tr>
				      <td bgcolor="#fffacd">
	    <h2>Table of Contents</h2>
	    <ul>
	    <xsl:apply-templates select="/api/files/file" mode="toc"/>
	    </ul>
					<p><a href="bugs.html">Daniel Veillard</a></p>
				      </td>
				    </tr>
				  </table>
				</td>
			      </tr>
			    </table>
			  </td>
			</tr>
		      </table>
		    </td>
		  </tr>
		</table>
	      </td>
	    </tr>
	  </table>
	  </body>
	</html>
    </xsl:document>
    <!-- now build the file for each of the modules -->
    <xsl:apply-templates select="/api/files/file"/>
  </xsl:template>

</xsl:stylesheet>
