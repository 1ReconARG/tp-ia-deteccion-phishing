"""
Agente detector de phishing - TP Final IA (0246), Grupo 10.

Implementa el agente que aprende de la Figura 4 del TP, con sus cuatro
componentes (Módulo 6, Aprendizaje):

  - Elemento de rendimiento: percibe el correo con sus sensores, el
    perceptrón multicapa estima la probabilidad de phishing y la capa de
    lógica difusa elige una de las tres acciones de la Tabla 2 (entregar,
    entregar con advertencia, cuarentena). Avisar a seguridad no es una
    cuarta acción: es un efector más (Tabla 3) que acompaña a la cuarentena
    y a la regla de sospecha alta con dominio antiguo.
  - Crítico: compara lo que hizo el agente con un estándar externo, las
    denuncias revisadas por un analista (datos/denuncias.csv).
  - Elemento de aprendizaje: reentrena el modelo sumando las denuncias y
    solo reemplaza la versión vigente si no empeora en VALIDACIÓN (la
    prueba no se usa para decidir).
  - Generador de problemas: los casos dudosos van a revisión
    (datos/a_revisar.csv): los que terminan con advertencia y aquellos en
    los que el árbol aprendido no coincide con el perceptrón multicapa.

Además muestra el árbol de decisión de costos de la cátedra (sección 4.2)
y explica cada decisión con las condiciones del árbol aprendido.
"""
import csv
import shutil
from pathlib import Path

import joblib

from phishing_ia import (DATOS, MODELO, anonimizar, cargar, dividir,
                         guardar_modelo, nuevo_vectorizador, nuevos_modelos)
from sklearn.metrics import accuracy_score, recall_score

DENUNCIAS = DATOS / "denuncias.csv"
A_REVISAR = DATOS / "a_revisar.csv"

# Costos de la Tabla 9 del TP (puntos, valores ilustrativos).
COSTOS = {
    "ENTREGAR": {"phishing": 100, "legitimo": 0},
    "ENTREGAR CON ADVERTENCIA": {"phishing": 30, "legitimo": 2},
    "CUARENTENA": {"phishing": 0, "legitimo": 20},
}
# Reglas de la sección 4.5: (nombre, acción, ¿avisa a seguridad?).
# Están en orden de prudencia: si dos empatan, gana la que aparece primero.
REGLAS = [
    ("alta Y dominio nuevo", "CUARENTENA", True),
    ("alta Y dominio antiguo", "ENTREGAR CON ADVERTENCIA", True),
    ("media", "ENTREGAR CON ADVERTENCIA", False),
    ("baja", "ENTREGAR", False),
]


# ------------------------------------------------------------ lógica difusa
def trapecio(x, a, b, c, d):
    """Función de pertenencia trapezoidal: sube de a a b, vale 1 de b a c y
    baja de c a d. Con b == c es un triángulo."""
    if b <= x <= c:
        return 1.0
    if a < x < b:
        return (x - a) / (b - a)
    if c < x < d:
        return (d - x) / (d - c)
    return 0.0


def sospecha(p):
    """Grados de pertenencia del nivel de sospecha (Figura 7 del TP)."""
    return {
        "baja": trapecio(p, 0.0, 0.0, 0.20, 0.45),
        "media": trapecio(p, 0.25, 0.50, 0.50, 0.75),
        "alta": trapecio(p, 0.55, 0.80, 1.0, 1.0),
    }


def decidir_difuso(p, dominio_nuevo):
    """Reglas de la sección 4.5. El Y difuso es el mínimo; el dominio
    antiguo es el complemento del nuevo (1 - μ). Gana la regla más activada
    y, si empatan, la más prudente. Devuelve la acción, si se avisa a
    seguridad, los grados de sospecha y la activación de cada regla."""
    s = sospecha(p)
    grado = {
        "alta Y dominio nuevo": min(s["alta"], dominio_nuevo),
        "alta Y dominio antiguo": min(s["alta"], 1 - dominio_nuevo),
        "media": s["media"],
        "baja": s["baja"],
    }
    mejor = max(grado.values())
    nombre, accion, aviso = next(r for r in REGLAS if grado[r[0]] == mejor)
    return accion, aviso, s, {r[0]: (r[1], r[2], grado[r[0]]) for r in REGLAS}


def arbol_de_costos(p):
    """Árbol de decisión de la cátedra: esperanza matemática en cada nodo de
    probabilidad y mínimo costo en el nodo de decisión."""
    esperados = {a: p * c["phishing"] + (1 - p) * c["legitimo"] for a, c in COSTOS.items()}
    return min(esperados, key=esperados.get), esperados


# ------------------------------------------------------------ el agente
class AgenteDetector:
    def __init__(self, carpeta=MODELO):
        archivo = carpeta / "detector.joblib"
        if not archivo.exists():
            raise SystemExit("No hay modelo entrenado: primero correr  python phishing_ia.py")
        m = joblib.load(archivo)
        self.vect, self.mlp, self.arbol = m["vectorizador"], m["mlp"], m["arbol"]

    # Sensores: leen el correo y lo convierten en la entrada del programa agente.
    def percibir(self, texto):
        limpio = " ".join(anonimizar(texto.lower()).split())
        return limpio, self.vect.transform([limpio])

    # Explicación: el camino que recorre el correo en el árbol aprendido.
    def explicar(self, vector):
        t = self.arbol.tree_
        palabras = self.vect.get_feature_names_out()
        nodo, pasos = 0, []
        while t.children_left[nodo] != -1:
            palabra = palabras[t.feature[nodo]]
            presente = vector[0, t.feature[nodo]] > t.threshold[nodo]
            pasos.append(f"{'aparece' if presente else 'no aparece'} «{palabra}»")
            nodo = t.children_right[nodo] if presente else t.children_left[nodo]
        clase = "phishing" if t.value[nodo][0].argmax() == 1 else "legítimo"
        return pasos, clase

    # Elemento de rendimiento.
    def actuar(self, texto, dominio_nuevo=0.5):
        limpio, vector = self.percibir(texto)
        p = float(self.mlp.predict_proba(vector)[0, 1])
        accion, aviso, grados, reglas = decidir_difuso(p, dominio_nuevo)
        accion_costos, esperados = arbol_de_costos(p)
        pasos, clase_arbol = self.explicar(vector)
        # La explicación solo vale si el árbol llega a la misma clase que el MLP.
        coincide = (clase_arbol == "phishing") == (p >= 0.5)
        motivos = []
        if accion == "ENTREGAR CON ADVERTENCIA":
            motivos.append("terminó con advertencia")
        if not coincide:
            motivos.append("el árbol aprendido no coincide con el perceptrón multicapa")
        if motivos:
            self.generador_de_problemas(limpio, p, "; ".join(motivos))
        return {"p": p, "accion": accion, "aviso": aviso, "sospecha": grados,
                "reglas": reglas, "accion_costos": accion_costos,
                "esperados": esperados, "explicacion": pasos,
                "clase_arbol": clase_arbol, "coincide": coincide,
                "a_revision": motivos}

    # Generador de problemas: los casos dudosos van a revisión.
    @staticmethod
    def generador_de_problemas(texto, p, motivo):
        nuevo = not A_REVISAR.exists()
        with open(A_REVISAR, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if nuevo:
                w.writerow(["texto", "probabilidad", "motivo"])
            w.writerow([texto, f"{p:.3f}", motivo])


# ------------------------------------------------------------ crítico
def critico_registrar(texto, es_phishing):
    """Guarda una denuncia revisada por un analista: es el estándar externo
    con el que se mide al agente."""
    nuevo = not DENUNCIAS.exists()
    with open(DENUNCIAS, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if nuevo:
            w.writerow(["texto", "clase"])
        w.writerow([" ".join(anonimizar(texto.lower()).split()),
                    "Phishing Email" if es_phishing else "Safe Email"])


# ------------------------------------------------------------ elemento de aprendizaje
def reentrenar():
    """Suma las denuncias al entrenamiento, reentrena y compara contra la
    versión vigente sobre el MISMO conjunto de VALIDACIÓN. Solo reemplaza el
    modelo si no empeora; la versión anterior queda en modelo/anterior/.
    El conjunto de prueba no se toca: decidir con él inflaría el resultado."""
    import pandas as pd
    df = cargar()
    x_train, x_val, _, y_train, y_val, _ = dividir(df)
    if DENUNCIAS.exists():
        den = pd.read_csv(DENUNCIAS)
        x_train = pd.concat([x_train, den["texto"]], ignore_index=True)
        y_train = pd.concat([y_train, (den["clase"] == "Phishing Email").astype(int)], ignore_index=True)
        print(f"Denuncias sumadas al entrenamiento: {len(den)}")
    else:
        print("No hay denuncias registradas: se reentrena con los datos originales.")

    vigente = AgenteDetector()
    antes = vigente.mlp.predict(vigente.vect.transform(x_val))

    vect = nuevo_vectorizador()
    v_train = vect.fit_transform(x_train)
    modelos = nuevos_modelos()
    for nombre in ("Perceptrón multicapa", "Árbol de decisión"):
        modelos[nombre].fit(v_train, y_train)
    despues = modelos["Perceptrón multicapa"].predict(vect.transform(x_val))

    a0, a1 = accuracy_score(y_val, antes), accuracy_score(y_val, despues)
    r0, r1 = recall_score(y_val, antes), recall_score(y_val, despues)
    print("Comparación sobre el conjunto de validación:")
    print(f"Versión vigente: exactitud {a0:.4f} · phishing detectado {r0:.4f}")
    print(f"Versión nueva:   exactitud {a1:.4f} · phishing detectado {r1:.4f}")
    if a1 >= a0 and r1 >= r0:
        anterior = MODELO / "anterior"
        anterior.mkdir(exist_ok=True)
        shutil.copy(MODELO / "detector.joblib", anterior / "detector.joblib")
        guardar_modelo(vect, modelos)
        print("Se adopta la versión nueva (la anterior queda en modelo/anterior/).")
    else:
        print("La versión nueva no mejora: se conserva la vigente.")


if __name__ == "__main__":
    reentrenar()
