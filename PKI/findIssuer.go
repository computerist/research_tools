package main

import (
  "crypto/x509"
  "encoding/pem"
  "flag"
  "fmt"
  "io/ioutil"
)

func check(e error) {
  if e != nil {
    panic(e)
  }
}

func loadCerts(filename string) ([]*x509.Certificate) {
  fmt.Println("loading certs from ", filename)
  dat, err := ioutil.ReadFile(filename)
  check(err)
  var certs []*x509.Certificate

  for len(dat) > 0 {
    var block *pem.Block
    block, dat = pem.Decode(dat)
    if block == nil {
      break
    }
    if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
      continue
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
      continue
    }

    certs = append(certs, cert)
  }
  return certs
}

func findCertSigner(certs []*x509.Certificate, cert *x509.Certificate) *x509.Certificate {
  for _, signer := range certs {

    var err = cert.CheckSignatureFrom(signer);
    if nil == err {
      return signer
    }
  }
  return nil
}

func main() {
  issuersPEMPtr := flag.String("issuers", "", "a PEM file containing possible issuer certs")
  searchPEMPtr := flag.String("searchCerts", "", "a PEM file containing certs you want to search for issuers of")

  var issuersMap = make(map[string][]*x509.Certificate)

  flag.Parse()

  //var issuersPool, searchCertPool *x509.CertPool
  var issuers, searchCerts []*x509.Certificate

  if nil != issuersPEMPtr && len(*issuersPEMPtr) > 0 {
    issuers = loadCerts(*issuersPEMPtr)
  }
  if nil != searchPEMPtr && len(*searchPEMPtr) > 0 {
    searchCerts = loadCerts(*searchPEMPtr)
  }

  for _, issuerCert := range issuers {
    var certs []*x509.Certificate
    if issuersMap[issuerCert.Subject.String()] == nil {
      certs = append(certs, issuerCert)
      issuersMap[issuerCert.Subject.String()] = certs
    } else {
      issuersMap[issuerCert.Subject.String()] = append(issuersMap[issuerCert.Subject.String()], issuerCert)
    }
  }

  var signer *x509.Certificate;

  for _, searchCert := range searchCerts {
    fmt.Println("checking", searchCert.Subject)
    var candidates = issuersMap[searchCert.Issuer.String()]
    signer = findCertSigner(candidates, searchCert)
    if nil != signer {
      fmt.Println("Issuer found in the issuers cert list.");
      fmt.Println("search cert: ", searchCert.Subject);
      fmt.Println("Signer cert: ", signer.Subject);
    }
  }
}
