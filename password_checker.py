import re

def check_password(password):
    """Avalia a força de uma senha com base em critérios de segurança.

    Returns:
        dict: dicionário com 'score' (0-5), 'strength' ('FRACA'|'MÉDIA'|'FORTE')
              e 'feedback' (lista de sugestões).
    """
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

    if score <= 2:
        strength = "FRACA"
    elif score <= 4:
        strength = "MÉDIA"
    else:
        strength = "FORTE"

    print("\n📊 Resultado:")
    icons = {"FRACA": "🔴", "MÉDIA": "🟡", "FORTE": "🟢"}
    print(f"  Força: {icons[strength]} {strength}")

    if feedback:
        print("\n💡 Sugestões:")
        for tip in feedback:
            print(f"  {tip}")

    return {"score": score, "strength": strength, "feedback": feedback}

if __name__ == "__main__":
    password = input("Digite a senha para verificar: ")
    check_password(password)
