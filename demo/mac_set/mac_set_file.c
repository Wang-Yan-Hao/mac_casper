#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mac.h>

/*
 * 使用方式: ./test_setlabel <檔案路徑> <標籤字串>
 * 範例: ./test_setlabel /tmp/test.txt casper/dns
 */
int main(int argc, char *argv[]) {
    mac_t label;
    int error;
    char *filepath;
    char *label_text;

    // 1. 檢查參數
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <filepath> <label_text>\n", argv[0]);
        fprintf(stderr, "Example: %s /tmp/foo.txt casper/dns\n", argv[0]);
        return 1;
    }

    filepath = argv[1];
    label_text = argv[2];

    // 2. 準備 MAC 結構 (mac_t)
    // mac_from_text 會解析字串，格式必須是 "policy_name/label_value"
    // 例如: "casper/dns"
    error = mac_from_text(&label, label_text);
    if (error != 0) {
        perror("mac_from_text failed (Format error?)");
        return 1;
    }

    // 3. 設定標籤 (核心動作)
    // 這會觸發 Kernel 裡的:
    // -> internalize (解析)
    // -> check_setlabel (檢查權限)
    // -> VOP_SETEXTATTR (寫入硬碟)
    // -> setlabel_extattr (同步記憶體)
    error = mac_set_file(filepath, label);

    if (error != 0) {
        perror("mac_set_file failed");
        // 常見錯誤:
        // EACCES (13): 不是 Root 或 check_setlabel 拒絕
        // EOPNOTSUPP (45): 檔案系統沒開 multilabel 或模組沒載入
        // ENOMEM (12): 記憶體不足
        mac_free(label);
        return 1;
    }

    // 4. 清理並回報成功
    mac_free(label);
    printf("SUCCESS: Set label '%s' on file '%s'\n", label_text, filepath);

    return 0;
}
