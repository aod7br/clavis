Solução do desafio Clavis
=========================

01/08/2016

Como encontrei uma boa biblioteca para a API charts do google no python
e a do perl não funcionou, vou desenvolver em python.

Vamos chamar a aplicação de chart\_CVE.py

O objetivo é receber uma lista de CVEs e buscar as informações com GETs
em
[https://web.nvd.nist.gov/view/vuln/detail?vulnId=\*](https://web.nvd.nist.gov/view/vuln/detail?vulnId=*).
Depois de parsear a pagina, vou armazenar as informacoes em um array. Execute o programa assim:

    python chart_CVE.py lista_CVE.txt

O arquivo TXT com a lista de CVE tera o seguinte formato (um CVE em cada
linha):

    CVE-2016-5511
    CVE-2016-5512
    CVE-2016-5513
    CVE-2016-5514
    CVE-2016-5515

Como output, o programa ira gerar 4 arquivos graficos:

-   chartV2.png

-   chartV3.png

-   barV2.png

-   barV3.png

E um arquivo contendo a tabela de CVEs contendo os seguintes dados:

-   tabela.csv

<!-- -->

    CVE_NUMBER, CVSSV2_SCORE, CVSSV2_IMPACT, CSSV2_EXPLOITABILITY, CVSSV3_SCORE, CVSSV3_IMPACT, CSSV3_EXPLOITABILITY

Instalação 
----------

Assumo que o python versão 2.6 ou 2.7 está instalado, e o instalador de
pacotes do python, *pip*, também está. Para executar o request GET
usarei a *urllib2* do python, ela é padrão na versão 2.X.

Vamos instalar o modulo para fazer o parse na página, este é um módulo
que já usei para fazer *crawlers*:

    pip install bs4

E o modulo para acessar a API do google
([https://github.com/gak/pygooglechart/tree/master/examples](https://github.com/gak/pygooglechart/tree/master/examples)).
Eu rodei os exemplos deste módulo e funcionaram perfeitamente.

    pip install pygooglechart

Fuçando até achei uma lista de CVEs para download aqui:
[https://cve.mitre.org/data/downloads/allitems.csv](https://cve.mitre.org/data/downloads/allitems.csv)
Baixei e gerei uma lista de teste com 10 items:

     cut -d, -f1 < allitems.csv | tail -2000 | head -10 >lista_CVE.txt

  ---- -----------------------------------------------------------------------------------------------
  **   Terminei o script, mas quando a lista de CVE é muito grande o grafico de barras fica confuso.
  ---- -----------------------------------------------------------------------------------------------

Andre Oliveira Dias \<[aod7br@gmail.com](mailto:aod7br@gmail.com)\>

Esta documentacao foi convertida de asciidoc para markdown, mas esta mais legivel no subdir doc
