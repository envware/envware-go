=== Comandos do Envware ===

// git envw <comando>

// Basics
clone <git-url>     Clona repo e conecta ao Envware
pull [team] [project]  Baixa e descriptografa secrets
push [team] [project] Criptografa e sobe secrets
status                 Mostra status do projeto

// Local Mode (sem servidor)
encrypt <file>         Criptografa arquivo localmente
decrypt <file> <out>   Descriptografa arquivo localmente

// Acesso
request <team> <project> <role>  Solicita acesso
accept [<id>]                   Aprova solicitação

// Device Management (SSH-based auth)
pair <code>         Pareia CLI com servidor (gere código no dashboard)
devices              Lista dispositivos pareados
unpair <device-id>  Remove dispositivo pareado

// Admin
fingerprint          Mostra sua fingerprint SSH
version              Versão do CLI
help                 Ajuda