"""
Prueba el agente con un correo y muestra cómo llega a su decisión.

Uso:
  python probar_correo.py ejemplos/01_banco_falso.txt
  python probar_correo.py ejemplos/01_banco_falso.txt --dominio-nuevo 0.9
  python probar_correo.py ejemplos/02_reunion.txt --denunciar legitimo

--dominio-nuevo  grado de pertenencia (0 a 1) del dominio del remitente al
                 conjunto difuso "dominio nuevo". Si no se sabe, 0,5.
--denunciar      registra la denuncia revisada (phishing / legitimo) para el
                 crítico; la próxima vez que se corra  python agente.py  el
                 agente se reentrena con ella.
"""
import argparse
import sys
from pathlib import Path

from agente import AgenteDetector, critico_registrar

sys.stdout.reconfigure(encoding="utf-8")
coma = lambda x, n=2: f"{x:.{n}f}".replace(".", ",")


def main():
    ap = argparse.ArgumentParser(description="Prueba el agente detector de phishing con un correo.")
    ap.add_argument("archivo", help="archivo .txt con el correo (asunto y cuerpo)")
    ap.add_argument("--dominio-nuevo", type=float, default=0.5,
                    help="grado (0 a 1) en que el dominio del remitente es nuevo. Se carga "
                         "a mano: el conjunto de datos no trae remitente y no se puede medir")
    ap.add_argument("--denunciar", choices=["phishing", "legitimo"])
    a = ap.parse_args()

    texto = Path(a.archivo).read_text(encoding="utf-8")
    r = AgenteDetector().actuar(texto, a.dominio_nuevo)

    print(f"\nCorreo: {a.archivo}")
    print("-" * 64)
    print(f"1. Perceptrón multicapa -> probabilidad de phishing: {coma(r['p'], 3)}")
    g = r["sospecha"]
    print(f"2. Sospecha (lógica difusa): baja {coma(g['baja'])} · media {coma(g['media'])} · alta {coma(g['alta'])}")
    print(f"   Dominio nuevo: {coma(a.dominio_nuevo)} · dominio antiguo (complemento): {coma(1 - a.dominio_nuevo)}")
    print("   Activación de cada regla (Y difuso = mínimo):")
    for nombre, (accion, aviso, grado) in r["reglas"].items():
        regla = f"SI sospecha {nombre} -> {accion}" + (" + aviso" if aviso else "")
        print(f"     {regla:<72} {coma(grado)}")
    print(f"   => ACCIÓN: {r['accion']}" + (" + AVISO AL ÁREA DE SEGURIDAD" if r["aviso"] else ""))
    print("3. Árbol de decisión de costos (esperanza matemática):")
    for accion, costo in r["esperados"].items():
        print(f"     {accion:<31} costo esperado {coma(costo, 1)}")
    print(f"   => menor costo esperado: {r['accion_costos']}")
    si = [x.split(" ", 1)[1] for x in r["explicacion"] if x.startswith("aparece")]
    no = [x.split(" ", 2)[2] for x in r["explicacion"] if x.startswith("no aparece")]
    if r["coincide"]:
        print(f"4. Por qué (camino en el árbol aprendido, que también dice «{r['clase_arbol']}»):")
        if si:
            print(f"     aparecen:    {', '.join(si)}")
        else:
            print(f"     no aparece ninguna de las palabras por las que pregunta: llega a «{r['clase_arbol']}» por descarte")
        print(f"     no aparecen: {', '.join(no[:6]) if no else '-'}" + (" ..." if len(no) > 6 else ""))
    else:
        print(f"4. Por qué: el árbol aprendido dice «{r['clase_arbol']}» y el perceptrón multicapa no.")
        print("     Su explicación no vale para este correo, así que no se muestra.")
    if r["a_revision"]:
        print(f"5. Generador de problemas: a revisión (datos/a_revisar.csv) porque {' y '.join(r['a_revision'])}.")
    if a.denunciar:
        critico_registrar(texto, a.denunciar == "phishing")
        print(f"Crítico: denuncia registrada como «{a.denunciar}» en datos/denuncias.csv.")
    print()


if __name__ == "__main__":
    main()
