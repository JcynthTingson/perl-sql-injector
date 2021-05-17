# perl-sql-injector
Perl script SQL Injector

It exploits SQLi vulnerability via UNION-BASED INT attack.

## Usage

```
perl sqli.pl <tagerhost> 80
```
Target host must not include `http://|https://|www`

## How this script works
It works by sending a request with sql malicious script and fetching the page using `LWP::UserAgent` module.<br>
And then parsing it with perl powerful regex and output the parsed result into the terminal.

## The Future and the past
This perl script is easy to read and if you are perl coder and a pentester? You can freely modify this code.<br>
Perl SQL Injector lacks the ability to exploit ERROR-BASED SQLi, UNION-BASED string SQLi, Blind-SQLi and Time-Based SQLi.<br>
This perl script was based on the Book: 'Penetration Testing with Perl' By Douglas Berdeaux
[https://www.packtpub.com/product/penetration-testing-with-perl/9781783283453](https://www.packtpub.com/product/penetration-testing-with-perl/9781783283453)
