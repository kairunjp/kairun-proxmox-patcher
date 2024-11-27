#!/bin/bash

# 対象ファイル
TARGET_FILE="/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"

# バックアップ作成
if [[ ! -f "${TARGET_FILE}.bak" ]]; then
    cp "$TARGET_FILE" "${TARGET_FILE}.bak"
    echo "バックアップを作成しました: ${TARGET_FILE}.bak"
fi

# 編集処理
sed -i.bak -E '
/Proxmox\.Utils\.API2Request\(/,/orig_cmd\(\);/ {
    s/if \(res === null || res === undefined || !res || res\n[[:space:]]+\.data\.status\.toLowerCase\(\) !== .active.\)/if (false)/g
}
' "$TARGET_FILE"

# 確認
if grep -q "if (false)" "$TARGET_FILE"; then
    echo "スクリプトが正常に実行されました。"
else
    echo "変更に失敗しました。元のファイルに戻すには次を実行してください:"
    echo "mv ${TARGET_FILE}.bak ${TARGET_FILE}"
fi
