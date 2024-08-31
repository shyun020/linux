#!/bin/bash

# 결과를 저장할 파일 이름 설정
resultfile="Results_$(date '+%m:%d_%H:%M').txt"

# BoB 로고 출력
echo " ________  ________  ________     " 
echo "|\   __  \|\   __  \|\   __  \    " 
echo "\ \  \|\ /\ \  \|\  \ \  \|\ /_   " 
echo " \ \   __  \ \  \\\  \ \   __  \  " 
echo "  \ \  \|\  \ \  \\\  \ \  \|\  \ " 
echo "   \ \_______\ \_______\ \_______\\"
echo "    \|_______|\|_______|\|_______|"
echo ""

# 결과를 파일에 저장하는 함수
print_and_save() {
    echo -e "$1" >> "$resultfile"
}

# 1. root 원격 접속 제한
check_root_login() {
    if [ -f /etc/ssh/ssh_config ]; then
        ROOT_LOGIN=$(grep "^PermitRootLogin" /etc/ssh/ssh_config | awk '{print $2}')
        total_checks=$((total_checks + 1))
        if [ "$ROOT_LOGIN" == "no" ]; then
            print_and_save "1. root 원격 접속: $ROOT_LOGIN - 양호"
            total_passed=$((total_passed + 1))
        else
            print_and_save "1. root 원격 접속: $ROOT_LOGIN - 취약"
            total_failed=$((total_failed + 1))
        fi
    else
        print_and_save "1. root 원격 접속: 파일을 찾을 수 없음 - 취약"
        total_failed=$((total_failed + 1))
    fi
    print_and_save "=============="
}

# 2. 패스워드 파일 보호
check_password_file_permissions() {
    if [ -f /etc/passwd ] && [ -f /etc/shadow ]; then
        PASSWD_PERM=$(stat -c "%a" /etc/passwd)
        SHADOW_PERM=$(stat -c "%a" /etc/shadow)
        total_checks=$((total_checks + 1))
        if [ "$PASSWD_PERM" == "644" ] && [ "$SHADOW_PERM" == "400" ]; then
            print_and_save "2. 패스워드 파일: /etc/passwd $PASSWD_PERM, /etc/shadow $SHADOW_PERM - 양호"
            total_passed=$((total_passed + 1))
        else
            print_and_save "2. 패스워드 파일: /etc/passwd $PASSWD_PERM, /etc/shadow $SHADOW_PERM - 취약"
            total_failed=$((total_failed + 1))
        fi
    else
        print_and_save "2. 패스워드 파일: 파일을 찾을 수 없음 - 취약"
        total_failed=$((total_failed + 1))
    fi
    print_and_save "=============="
}

# 3. 패스워드 복잡성
check_password_complexity() {
    if grep -q "^PASS_MIN_LEN" /etc/login.defs; then
        PASS_MIN_LEN=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}')
        total_checks=$((total_checks + 1))
        if [ "$PASS_MIN_LEN" -ge 8 ]; then
            print_and_save "3. 패스워드 복잡성: 최소 길이 $PASS_MIN_LEN - 양호"
            total_passed=$((total_passed + 1))
        else
            print_and_save "3. 패스워드 복잡성: 최소 길이 $PASS_MIN_LEN - 취약"
            total_failed=$((total_failed + 1))
        fi
    else
        print_and_save "3. 패스워드 복잡성: 설정을 찾을 수 없음 - 취약"
        total_failed=$((total_failed + 1))
    fi
    print_and_save "=============="
}

# 4. 계정 잠금 임계값
check_account_lock() {
    if grep -q "pam_tally2" /etc/pam.d/common-auth; then
        LOCK_THRESHOLD=$(grep "pam_tally2" /etc/pam.d/common-auth | grep "deny=" | awk -F 'deny=' '{print $2}' | awk '{print $1}')
        total_checks=$((total_checks + 1))
        if [ "$LOCK_THRESHOLD" -le 10 ]; then
            print_and_save "4. 잠금 임계값: $LOCK_THRESHOLD - 양호"
            total_passed=$((total_passed + 1))
        else
            print_and_save "4. 잠금 임계값: $LOCK_THRESHOLD - 취약"
            total_failed=$((total_failed + 1))
        fi
    else
        print_and_save "4. 잠금 임계값: 설정을 찾을 수 없음 - 취약"
        total_failed=$((total_failed + 1))
    fi
    print_and_save "=============="
}

# 5. 불필요 계정 제거
check_unnecessary_accounts() {
    UNNECESSARY_ACCOUNTS=$(egrep -v "/bin/false|/usr/sbin/nologin|/sbin/nologin" /etc/passwd | awk -F: '($3 < 1000) && ($3 != 0) {print $1}')
    total_checks=$((total_checks + 1))
    if [ -z "$UNNECESSARY_ACCOUNTS" ]; then
        print_and_save "5. 불필요 계정: 없음 - 양호"
        total_passed=$((total_passed + 1))
    else
        print_and_save "5. 불필요 계정: 존재 - 취약"
        total_failed=$((total_failed + 1))
    fi
    print_and_save "=============="
}

# 6. 홈 디렉토리 권한
check_home_directory_permissions() {
    HOME_DIRS=$(awk -F: '{ print $6 }' /etc/passwd | sort | uniq)
    for dir in $HOME_DIRS; do
        if [ -d "$dir" ]; then
            PERM=$(stat -c "%a" "$dir" 2>/dev/null)
            total_checks=$((total_checks + 1))
            if [ -z "$PERM" ]; then
                print_and_save "6. 홈 디렉토리: $dir 권한 정보 없음 - 취약"
                total_failed=$((total_failed + 1))
            elif [ "$PERM" -le 755 ]; then
                print_and_save "6. 홈 디렉토리: $dir $PERM - 양호"
                total_passed=$((total_passed + 1))
            else
                print_and_save "6. 홈 디렉토리: $dir $PERM - 취약"
                total_failed=$((total_failed + 1))
            fi
        else
            print_and_save "6. 홈 디렉토리: $dir 없음 - 취약"
            total_failed=$((total_failed + 1))
        fi
    done
    print_and_save "=============="
}

# 7. 로그인 이력 확인
check_login_history() {
    LAST_LOGINS=$(lastlog | grep -v "Never" | awk '{print $1, $3, $4, $5, $6, $7, $8, $9}')
    total_checks=$((total_checks + 1))
    if [ -z "$LAST_LOGINS" ]; then
        print_and_save "7. 로그인 이력: 이상 없음 - 양호"
        total_passed=$((total_passed + 1))
    else
        print_and_save "7. 로그인 이력: 의심스러운 이력 있음 - 취약"
        total_failed=$((total_failed + 1))
    fi
    print_and_save "=============="
}

# 8. UMASK 설정
check_umask_settings() {
    if grep -q "umask" /etc/profile /etc/bash.bashrc /etc/login.defs; then
        UMASK_VALUE=$(grep -i "umask" /etc/profile /etc/bash.bashrc /etc/login.defs | grep -v "#" | awk '{print $2}')
        total_checks=$((total_checks + 1))
        if [ "$UMASK_VALUE" == "022" ]; then
            print_and_save "8. UMASK 설정: $UMASK_VALUE - 양호"
            total_passed=$((total_passed + 1))
        else
            print_and_save "8. UMASK 설정: $UMASK_VALUE - 취약"
            total_failed=$((total_failed + 1))
        fi
    else
        print_and_save "8. UMASK 설정: 설정을 찾을 수 없음 - 취약"
        total_failed=$((total_failed + 1))
    fi
    print_and_save "=============="
}

# 9. SUID/SGID 파일 점검
check_suid_sgid_files() {
    DIRECTORIES=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
    SUID_SGID_FILES=""
    
    for DIR in "${DIRECTORIES[@]}"; do
        if [ -d "$DIR" ]; then
            SUID_SGID_FILES+=$(find "$DIR" -perm /6000 -type f 2>/dev/null)
        fi
    done
    
    total_checks=$((total_checks + 1))
    if [ -z "$SUID_SGID_FILES" ]; then
        print_and_save "9. SUID/SGID 파일: 없음 - 양호"
        total_passed=$((total_passed + 1))
    else
        print_and_save "9. SUID/SGID 파일: 존재 - 취약"
        total_failed=$((total_failed + 1))
    fi
    print_and_save "=============="
}

# 10. 홈 디렉토리 소유자
check_home_directory_ownership() {
    HOME_DIRS=$(awk -F: '{ print $6 }' /etc/passwd | sort | uniq)
    for dir in $HOME_DIRS; do
        if [ -d "$dir" ]; then
            OWNER=$(stat -c "%U" "$dir" 2>/dev/null)
            total_checks=$((total_checks + 1))
            if [ "$OWNER" == "$(basename $dir)" ]; then
                print_and_save "10. 홈 소유자: $dir $OWNER - 양호"
                total_passed=$((total_passed + 1))
            else
                print_and_save "10. 홈 소유자: $dir $OWNER - 취약"
                total_failed=$((total_failed + 1))
            fi
        else
            print_and_save "10. 홈 소유자: $dir 없음 - 취약"
            total_failed=$((total_failed + 1))
        fi
    done
    print_and_save "=============="
}

# 항목 점검 수행
check_root_login
check_password_file_permissions
check_password_complexity
check_account_lock
check_unnecessary_accounts
check_home_directory_permissions
check_login_history
check_umask_settings
check_suid_sgid_files
check_home_directory_ownership

# 최종 결과 출력 및 저장
print_and_save "\n총 $total_checks 항목 점검 / $total_failed 취약 / $total_passed 양호"

# 파일 저장 위치 출력
echo "결과가 $resultfile 파일에 저장되었습니다."
