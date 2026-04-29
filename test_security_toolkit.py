"""
Testes unitários — Security Toolkit
Disciplina: DevOps | Semana 8 — Atividade Somativa
"""

import hashlib
import io
import sys
import unittest
from unittest.mock import patch, MagicMock

# Garante UTF-8 no stdout/stderr (necessário no Windows com CP1252)
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

from hash_generator import generate_hash
from password_checker import check_password
from port_scanner import scan_ports


# ─────────────────────────────────────────────
# 1. Testes: hash_generator.py
# ─────────────────────────────────────────────

class TestHashGenerator(unittest.TestCase):

    def test_md5_valor_conhecido(self):
        """MD5 de 'hello' deve corresponder ao valor canônico."""
        resultado = generate_hash("hello")
        esperado = hashlib.md5(b"hello").hexdigest()
        self.assertEqual(resultado["md5"], esperado)

    def test_sha256_valor_conhecido(self):
        """SHA-256 de 'hello' deve corresponder ao valor canônico."""
        resultado = generate_hash("hello")
        esperado = hashlib.sha256(b"hello").hexdigest()
        self.assertEqual(resultado["sha256"], esperado)

    def test_sha512_valor_conhecido(self):
        """SHA-512 de 'hello' deve corresponder ao valor canônico."""
        resultado = generate_hash("hello")
        esperado = hashlib.sha512(b"hello").hexdigest()
        self.assertEqual(resultado["sha512"], esperado)

    def test_retorna_chaves_corretas(self):
        """O dicionário retornado deve conter exatamente as chaves esperadas."""
        resultado = generate_hash("segurança")
        self.assertSetEqual(set(resultado.keys()), {"md5", "sha256", "sha512"})

    def test_string_vazia(self):
        """Deve processar string vazia sem lançar exceção."""
        resultado = generate_hash("")
        self.assertIsNotNone(resultado["md5"])
        self.assertIsNotNone(resultado["sha256"])

    def test_hashes_diferentes_entre_si(self):
        """MD5, SHA-256 e SHA-512 de um mesmo texto devem ser distintos."""
        resultado = generate_hash("test123")
        valores = list(resultado.values())
        self.assertEqual(len(valores), len(set(valores)))


# ─────────────────────────────────────────────
# 2. Testes: password_checker.py
# ─────────────────────────────────────────────

class TestPasswordChecker(unittest.TestCase):

    def test_senha_forte(self):
        """Senha com todos os critérios atendidos deve ser classificada como FORTE."""
        resultado = check_password("Senha@123")
        self.assertEqual(resultado["strength"], "FORTE")
        self.assertEqual(resultado["score"], 5)

    def test_senha_fraca_curta(self):
        """Senha com apenas letras minúsculas curtas deve ser FRACA."""
        resultado = check_password("abc")
        self.assertEqual(resultado["strength"], "FRACA")
        self.assertIn("❌ Mínimo de 8 caracteres", resultado["feedback"])

    def test_senha_media(self):
        """Senha sem caracteres especiais deve ser classificada como MÉDIA."""
        resultado = check_password("Senha1234")
        self.assertEqual(resultado["strength"], "MÉDIA")

    def test_sem_maiusculas(self):
        """Deve indicar ausência de letras maiúsculas no feedback."""
        resultado = check_password("senha@123")
        self.assertIn("❌ Adicione letras maiúsculas", resultado["feedback"])

    def test_sem_numeros(self):
        """Deve indicar ausência de números no feedback."""
        resultado = check_password("Senha@abc")
        self.assertIn("❌ Adicione números", resultado["feedback"])

    def test_sem_especiais(self):
        """Deve indicar ausência de caracteres especiais no feedback."""
        resultado = check_password("Senha1234")
        self.assertIn("❌ Adicione caracteres especiais (!@#$...)", resultado["feedback"])

    def test_score_maximo(self):
        """Score máximo é 5 (todos os critérios atendidos)."""
        resultado = check_password("Abcdef@1")
        self.assertEqual(resultado["score"], 5)

    def test_score_minimo(self):
        """Senha de 1 caractere sem nenhum critério deve ter score baixo."""
        resultado = check_password("a")
        self.assertLessEqual(resultado["score"], 2)


# ─────────────────────────────────────────────
# 3. Testes: port_scanner.py (com mock de socket)
# ─────────────────────────────────────────────

class TestPortScanner(unittest.TestCase):

    @patch("port_scanner.socket.socket")
    def test_porta_aberta(self, mock_socket_class):
        """connect_ex retornando 0 deve indicar porta aberta (sem exceção)."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        # Não deve levantar exceção
        scan_ports("127.0.0.1", [80])

        mock_sock.connect_ex.assert_called_once_with(("127.0.0.1", 80))

    @patch("port_scanner.socket.socket")
    def test_porta_fechada(self, mock_socket_class):
        """connect_ex retornando != 0 deve indicar porta fechada (sem exceção)."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # porta fechada
        mock_socket_class.return_value = mock_sock

        scan_ports("127.0.0.1", [9999])

        mock_sock.connect_ex.assert_called_once_with(("127.0.0.1", 9999))


if __name__ == "__main__":
    unittest.main()
