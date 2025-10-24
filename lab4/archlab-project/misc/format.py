formated_lines = []

with open("bubble.ys", "r") as f:
    lines = f.readlines()
    for line in lines:
        formated_lines.append(line.strip().split("|")[1])

with open("bubble_formated.ys", "w") as f:
    for line in formated_lines:
        f.write(line + "\n")
