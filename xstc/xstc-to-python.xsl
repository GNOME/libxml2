<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:output method="text"/>   
    <!-- Main template. -->
    <xsl:template match="/">
        <xsl:text>#!/usr/bin/python -u
#
# This file is generated from the W3C test suite description file.
#

from xstc import MSTestRunner, MSTestCase

r = MSTestRunner()
                                 
</xsl:text>         
        <xsl:apply-templates select="tests/test"/>
        <xsl:text>
           
r.run() 
    
##################
# Display results.      
#

</xsl:text>
            
    </xsl:template>
        
    <!-- Test template. --> 

    <xsl:template match="file">
        <xsl:text>"</xsl:text>
        <xsl:value-of select="@folder"/><xsl:text>", "</xsl:text>
        <xsl:value-of select="@fileName"/><xsl:text>", </xsl:text>
        <xsl:value-of select="@validity"/>
    </xsl:template>
                    
    <xsl:template match="test">
        <xsl:text>r.addTest(MSTestCase("</xsl:text>
        <xsl:value-of select="@id"/>
        <xsl:text>", """</xsl:text>   
        <xsl:value-of select="description/text()"/>
        <xsl:text>""", "</xsl:text>       
        <xsl:value-of select="files/file[@role='schema']/@tsDir"/>
        <xsl:text>", </xsl:text>
        <xsl:choose>
            <xsl:when test="count(files/file[@role='schema']) = 1">
                <xsl:apply-templates select="files/file[@role='schema']"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:text>"", "", 0</xsl:text>
            </xsl:otherwise>
        </xsl:choose>
        <xsl:choose>
            <xsl:when test="count(files/file[@role='instance']) = 1">
                <xsl:text>, 1, </xsl:text>
                <xsl:apply-templates select="files/file[@role='instance']"/>
            </xsl:when>
            <xsl:otherwise>, 0, "", "", 0</xsl:otherwise>
        </xsl:choose>
        <xsl:text>))
</xsl:text>     
    </xsl:template>             
        
</xsl:stylesheet>
