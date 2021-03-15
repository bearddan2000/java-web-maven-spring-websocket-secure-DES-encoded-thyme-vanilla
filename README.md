# java-web-maven-spring-websocket-secure-DES-encoded-thyme-vanilla

## Description
This is a maven built springboot web app
using the STOMP subprotocol to communicate
over websockets to vanilla javascript thymeleaf clients.
By clients, we mean any number of visitors to
this website will see changes in real time.
  Security was added so that the insecure page `/login` will
be redirected to when hitting a secure page. DES was used
to encrypt and BCrypt to encode the password.
  The project is simple, the visitor clicks a
button which is updated on the server as well as
a log. Any new visitor will receive all logs and
an updated click count.

## Tech stack
- java
- maven
  - springboot
  - thymeleaf
  - bootstrap
  - jquery
  - sockjs

## Docker stack
- openjdk:11-jdk

## To run
`sudo ./install.sh -u`
Available at http://localhost
Login with id: user and password: pass

## To stop
`sudo ./install.sh -d`

## For help
`sudo ./install.sh -h`

## Credit
- https://spring.io/guides/gs/messaging-stomp-websocket/
- https://spring.io/guides/gs/securing-web/
- https://www.baeldung.com/spring-security-logout
