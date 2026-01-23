# PSIVS (PUP Services Injection Vulnerability Scanner)  

PSIVS is a Injection Vulnerabilty Scanner that allows developer  
to identify and remidiate critical vulnerabilities it crawls the  
URL and finds endpoint to scan for vulnerabilities like SQLI and  
XSS (more web vulnerabilities to be added in the future) and it   
generates a report that can help the developer fix security flaws  
that PSIVS found.  

## Installation  

download Go at https://go.dev/doc/install  

### Install katana  

```  
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest  
```  

### Clone the PSVIS repository  

```  
git clone https://github.com/xanxandra/PSIVS.git   
```  

