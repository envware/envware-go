push {TEAM} {PROJECT} {ENV}
pull {TEAM} {PROJECT} {ENV}

status {TEAM} [PROJECT]

request TEAM PROJECT ROLE
fingerprint
accept FINGERPRINT

backup {TEAM} {PROJECT} - baixa secrets criptografado
restore {TEAM} {PROJECT} - envia backup secrests

purchase TEAM PLAN [--cancel] - compra um novo team
purchase USERS {TEAM} {PROJECT} - compra 10 usuarios

---- apenas para role CI
show TEAM PROJECT ENV SECRET

----

roles fixas
------
OWNER - purchase, purchase --cancel
ADMIN - push, pull,accept
DEV - pull
SERVER - pull
CI - show


-------------
exemplos

push google chrome .env
push google chrome .env.development
pull google chrome .env.production

status google - lista todos os projetos do team google
status google chrome - lista todos os usuarios do projeto chrome

---------------------
novos precos e planos
FREE - 1 TEAM, 3 PROJETOS, 5 USERS/PROJETOS

TEAM EXTRA - 5 PROJETOS, 10 USERS/PROJETOS - 10USD
USER EXTRA - 10 USERS aplicado a um team/projeto - 10USD





