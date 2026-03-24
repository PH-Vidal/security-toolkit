import re

def check_password(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Mínimo de 8 caracteres")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("❌ Adicione letras maiúsculas")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("❌ Adicione letras minúsculas")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("❌ Adicione números")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("❌ Adicione caracteres especiais (!@#$...)")

    print("\n📊 Resultado:")
    if score <= 2:
        print("  Força: 🔴 FRACA")
    elif score <= 4:
        print("  Força: 🟡 MÉDIA")
    else:
        print("  Força: 🟢 FORTE")

    if feedback:
        print("\n💡 Sugestões:")
        for tip in feedback:
            print(f"  {tip}")

if __name__ == "__main__":
    password = input("Digite a senha para verificar: ")
    check_password(password)