# Profile Information

- Name: 최덕경 / Choi Deok Gyeong
- Email: hjcdg1@snu.ac.kr
- Phone: 010-4582-5037

# About Development

- Environment: `Ubuntu 20.04.3 LTS on Windows 10 x86_64` (WSL)
  - OS: Debian GNU/Linux 12 (bookworm)
  - Programming Language: Python 3.12
  - OpenSSL 1.1.1f
- Libraries
  - pyOpenSSL 23.3.0
  - cryptography 41.0.5
  - requests 2.31.0
- Execution
  - `python run.py [-v|-o] <host>`
  - Compilation is not required

# Note: Cross-Signed Certificate

몇몇 서버(EX. sha256.badssl.com)의 경우, 인증서 체인의 가장 상위 인증서(이하 C)는 Self-Signed 인증서가 아닌데 issuer 인증서도
로컬의 Trusted Store에 존재하지 않는다. 그러나 대부분의 브라우저 또는 OpenSSL 클라이언트로 검증을 시도하면 검증에 실패하지 않는다.
이는 C와 subject가 같지만 Self-Signed 되어 있는 다른 인증서가 로컬의 Trusted Store에 존재하기 때문이다.

> 실제로 서버가 내려준 인증서 C는 인증서 만료에 따른 하위 호환성을 보장하기 위한 Cross-Singed 인증서이다.

즉, 단순히 가장 상위 인증서의 issuer 인증서를 로컬의 Trusted Store에서 찾는 로직만으로는 올바른 검증이 이뤄지지 않는다.
따라서 다음과 같이 예외를 처리하였다.

> C가 Self-Signed가 아닌데 issuer 인증서가 로컬의 Trusted Store에 존재하지 않을 때, C와 동일한 이름(subject 기준)의 Self-Signed 인증서가 로컬의 Trusted Store에 존재한다면, 인증서 체인에서 C를 그 인증서로 대체한다.

이후, 해당 인증서 체인을 바탕으로 동일하게 검증 및 출력을 진행한다.