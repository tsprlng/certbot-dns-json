# Certbot JSON DNS plugin

To make it easier to automate external DNS changes requested by certbot, this is a certbot plugin which just prints all the challenges in a parseable format and then waits for input before proceeding to verification.

Initially this is a fork of https://github.com/EnigmaBridge/certbot-external-auth but I've modified it to not print the challenges one at a time, and will probably rip bits out and simplify it to be very tiny and just do the one job I actually need it for.
