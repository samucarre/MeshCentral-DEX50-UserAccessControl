# DEX50 User Access Control (MeshCentral Plugin)

**Blocks or deletes users on login based on DEX50 backend status.**

- Calls `https://backend.dex50.com/api/checkAccess?email=<user@email>` (must return `{ allow: boolean, reason?: string }`).
- If `allow:false`, the plugin:
  - Denies access immediately (HTTP 403),
  - And (policy A) tries to **delete the user from MeshCentral**.

## Requirements

- MeshCentral >= **1.1.80** (plugins support).
- Admin access to edit `/home/meshcentral/meshcentral-data/config.json`.

## Install (local folder)

1. Enable plugins in MeshCentral config:
   ```json
   {
     "settings": {
       "plugins": { "enabled": true }
     }
   }
