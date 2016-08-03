#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""

Desafio clavis
02082016

"""

import os
import sys
import urllib2
import re
from bs4 import BeautifulSoup
from pygooglechart import StackedHorizontalBarChart, \
                          GroupedHorizontalBarChart, \
                          PieChart2D, Axis
import settings #local settings


def bar_chart_cve(data, labels, filename, title):
    chart = StackedHorizontalBarChart(settings.width, settings.height,
                                      x_range=(0, 10))
    chart.set_bar_width(10)
    chart.set_title(title)
    chart.set_legend([ 'Impacto','Exploitabilidade'])
    chart.set_colours(['0000ff', 'ff0000'])
    chart.set_legend_position('r')
    chart.set_axis_labels(Axis.LEFT, labels)
    chart.add_data(data)
    chart.download(filename)


def pie_chart_cve( data, filename, title ):
    chart = PieChart2D(int(settings.width * 1.7), settings.height)
    chart.set_legend([  'Baixo', 'Médio',
                        'Alto', 'Crítico'])
    chart.set_title(title)
    chart.add_data(data)
    chart.set_colours(['00ff00','0000ff','ffff00','ff0000'])
    #chart.set_pie_labels([ 'Baixo', 'Médio', 'Alto', 'Crítico'])
    chart.download(filename)


def read_cve_file( filename ):
    file = open(filename, 'r')
    cve_list=[]
    for line in file:
        cve_list.append(line.rstrip())
    file.close()
    return cve_list


def create_cve_csv( filename, data_list ):
    file = open(filename, 'w')
    for row in data_list:
        file.write( '%s\n' % ', '.join(row) )
    file.close()


def parse_nist_page(url):
    resp = urllib2.urlopen( url )
    soup = BeautifulSoup( resp, 'lxml',
                      from_encoding=resp.info().getparam('charset') )
    text=soup.get_text().encode('utf-8')

    CVSSV2_SCORE=CVSSV2_IMPACT=CVSSV2_EXPLOITABILITY=None
    m=re.search(r'CVSS v2 Base Score:\s*([\w|\.]+)', text)
    if (m):
        CVSSV2_SCORE=m.group(1)
        iter_impact=re.finditer(r'Impact Subscore:\s*([\w|\.]+)', text)
        CVSSV2_IMPACT=iter_impact.next().group(1)
        iter_exploit=re.finditer(r'Exploitability Subscore:\s*([\w|\.]+)', text)
        CVSSV2_EXPLOITABILITY=iter_exploit.next().group(1)

    CVSSV3_SCORE=CVSSV3_IMPACT=CVSSV3_EXPLOITABILITY=None
    m=re.search(r'CVSS v3 Base Score:\s*([\w|\.]+)', text)
    if (m):
        CVSSV3_SCORE=m.group(1)
        iter_impact=re.finditer(r'Impact Subscore:\s*([\w|\.]+)', text)
        CVSSV3_IMPACT=iter_impact.next().group(1)
        iter_exploit=re.finditer(r'Exploitability Subscore:\s*([\w|\.]+)', text)
        CVSSV3_EXPLOITABILITY=iter_exploit.next().group(1)

    return [CVSSV2_SCORE, CVSSV2_IMPACT, CVSSV2_EXPLOITABILITY,
            CVSSV3_SCORE, CVSSV3_IMPACT, CVSSV3_EXPLOITABILITY]


def main():
    if (len(sys.argv)>1):
        cve_list=read_cve_file(sys.argv[1])
    else:
        sys.exit("ERROR: Please enter cve filename")

    tabela=[]
    barv2_data=[]
    barv2_labels=[]
    barv3_data=[]
    barv3_labels=[]
    for cve in cve_list:
        url='https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s' % cve
        try:
            extracted_data=parse_nist_page( url )
            (CVSSV2_SCORE, CVSSV2_IMPACT, CVSSV2_EXPLOITABILITY,
            CVSSV3_SCORE, CVSSV3_IMPACT, CVSSV3_EXPLOITABILITY)=extracted_data
            tabela.append( [cve]+extracted_data )

            barv2_data += [ float(CVSSV2_IMPACT), float(CVSSV2_EXPLOITABILITY) ]
            barv2_labels += [ '', cve ]

            barv3_data += [ float(CVSSV3_IMPACT), float(CVSSV3_EXPLOITABILITY) ]
            barv3_labels += [ '', cve ]

        except Exception, e:
            print "[%s] %s" % (e,url)

    bar_chart_cve( barv2_data, barv2_labels , 'output/barV2.png',
         'CVE-Impacto-Exploitabilidade V2' )

    bar_chart_cve( barv3_data, barv3_labels , 'output/barV3.png',
         'CVE-Impacto-Exploitabilidade V3' )

    #pie_chart_cve([10, 10, 30, 200], 'chartV2.png', 'CVE-CVSS V2 acumulado')

    #pie_chart_cve([2, 13, 23, 120], 'chartV3.png', 'CVE-CVSS V3 acumulado')

    create_cve_csv( 'output/tabela.csv', tabela)


if __name__ == '__main__':
    main()
