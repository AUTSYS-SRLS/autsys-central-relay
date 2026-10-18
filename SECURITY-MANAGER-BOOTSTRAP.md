# AUTSYS Central Relay — riconoscimento Manager con prima chiave fissa

## Decisione operativa (18 ottobre 2026)

AUTSYS Manager (Windows e Android) e AUTSYS Centrale **non cambiano**.
Il solo Central Relay associa ad ogni `installation_id` la prima coppia ricevuta:
`{platform, SHA256(binding_secret)}`. La chiave è già generata e conservata dal
Manager. Una volta salvata, tutti i collegamenti devono presentare la stessa
chiave, altrimenti restituiamo HTTP 401.

La prima chiave viene accettata senza certificare preventivamente l'identità
del dispositivo (trust on first use / TOFU), **anche per le nuove installazioni**.
Questo rischio è stato esplicitamente accettato dalla committenza per evitare
qualunque aggiornamento o intervento sui Manager. Se un attaccante con un ID
noto registra una chiave per primo, può bloccare il dispositivo autentico:
questa configurazione non elimina tale possibilità iniziale.

## Archivio persistente

Instance Render Key Value esclusiva del Relay:
`autsys-central-relay-manager-bindings`, ID `red-dbacgfijnfac73f6qnb0`,
regione Frankfurt, piano Starter, persistenza `journal_snapshot`, policy
`noeviction`.

Variabili ambiente del web service `autsys-central-relay`:
- `AUTSYS_MANAGER_BINDING_MODE=TOFU`
- `AUTSYS_MANAGER_BINDINGS_REDIS_URL=redis://red-dbacgfijnfac73f6qnb0:6379`
- `AUTSYS_MANAGER_BINDINGS_JSON` (opzionale, registrazioni amministrative preapprovate, solo SHA-256)

Il registro Redis è condiviso tra processi, usa `SET NX` per la prima
registrazione atomica e **nessuna scadenza**. Su Redis non memorizzare mai la
chiave segreta in chiaro, soltanto impronta SHA-256 e piattaforma.

La persistenza `journal_snapshot` protegge dai normali riavvii, ma Render
documenta che si può perdere fino all'ultimo secondo di scritture in caso di
arresto improvviso. Non è una garanzia di conservazione assoluta; fare
backup/snapshot operativi del registro secondo i criteri infrastrutturali AUTSYS.

## Deploy e controllo

1. Non modificare il protocollo Manager/Centrale e non imporre installazioni
   o conferme all'operatore.
2. Verificare che Redis sia disponibile prima di avviare la nuova versione Relay;
   il servizio **non parte** se non riesce a collegarsi al registro.
3. Eseguire test integrazione con Redis: prima chiave accettata, stessa chiave
   riutilizzabile, chiave diversa rifiutata, collisioni simultanee, riavvio.
4. Applicare le variabili Render prima del merge; un aggiornamento delle variabili
   potrebbe provocare il ridistribuire del codice vecchio, che le ignora.
5. Fare merge su `main` soltanto dopo CI verde. Render fa autodeploy.
6. Controllare che il deploy sia `live` e che riceva connessioni legittime
   dai Manager esistenti, in particolare SERVER e ZAMANA; non bloccare le
   installazioni temporaneamente spente.
7. Se Redis non fosse disponibile, rispondere 503 alle autenticazioni invece
   di accettare una nuova chiave al buio. Indagare e ripristinare.
8. Evitare i rollback al codice vulnerabile senza accettare l'esplicita perdita
   della protezione. Se un vecchio codice venisse riattivato, non dare per
   acquisito che le sue autorizzazioni rispettino il registro.

## Modello di sicurezza

Il Relay continua a gestire il solo trasporto e **non decide le licenze**:
il DB di AUTSYS Centrale resta autoritativo per licenze e catalogo.
L'autenticazione TOFU del Relay riguarda esclusivamente l'associazione
identificativo Manager / impronta chiave.

I token esistenti restano validi finché non scadono soltanto se la loro chiave
corrisponde a quella fissata nel registro. Se il registro non ha ancora
l'associazione, anche il primo accesso con token già valido può fissarla.
Il mancato allineamento di una chiave non provoca sostituzioni automatiche.
Una reinstallazione con nuovo binding ma stesso ID va diagnosticata da un
amministratore nel sistema, senza prevedere prompt agli operatori.
