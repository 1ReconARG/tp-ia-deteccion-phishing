"""
TP Final IA (0246) - Detección de correos de phishing - Grupo 10.
Integrantes: Alan Bazarian, Elias Joshua Caero, Ignacio Pacheco,
Mateo Valenzuela y Valentino Albarian.

Prototipo: entrena y compara cuatro recursos vistos en la materia sobre el
mismo conjunto público de correos etiquetados (aprendizaje supervisado):
  1) Red bayesiana: el nodo "phishing" influye sobre cada palabra, y las
     palabras se suponen independientes entre sí dada la clase.
  2) Árbol de decisión aprendido de los ejemplos.
  3) Perceptrón simple.
  4) Perceptrón multicapa con activación sigmoidea, entrenado con
     backpropagation y descenso de gradiente.

Con el conjunto de VALIDACIÓN se elige el umbral del perceptrón multicapa
(sección 5.5 del TP); el de PRUEBA se usa una sola vez, al final.

Nombres de la biblioteca: scikit-learn llama TfidfVectorizer a la
representación numérica de la sección 2.4 (un peso por palabra) y
MultinomialNB a la red bayesiana de la sección 4.3 (nodo "phishing" con una
flecha a cada palabra e independencia condicional).

Además guarda en modelo/ lo que usa el agente (agente.py): el vectorizador,
el perceptrón multicapa y el árbol.

Uso:      python phishing_ia.py
Requiere: pandas, scikit-learn, matplotlib (ver requirements.txt).
"""
import re
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import Perceptron
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import (ConfusionMatrixDisplay, accuracy_score,
                             confusion_matrix, precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier, plot_tree

BASE = Path(__file__).parent
DATOS = BASE / "datos"
SALIDA = BASE / "resultados"
SALIDA.mkdir(exist_ok=True)
MODELO = BASE / "modelo"
SEMILLA = 42


# ------------------------------------------------------------ 1. Datos
def anonimizar(texto: str) -> str:
    """Oculta datos sensibles: direcciones de correo, URL y números largos
    (teléfonos, documentos, tarjetas). Se reemplazan por una marca, así el
    modelo sigue sabiendo QUE había un enlace, pero no CUÁL."""
    texto = re.sub(r"\S+@\S+", " <EMAIL> ", texto)
    texto = re.sub(r"(https?://|www\.)\S+", " <URL> ", texto)
    texto = re.sub(r"\d{6,}", " <NUM> ", texto)
    return texto


def cargar() -> pd.DataFrame:
    anon = DATOS / "correos_anonimizados.csv"
    if anon.exists():                       # versión publicada en el repositorio
        df = pd.read_csv(anon)
        print(f"Correos (ya limpios y anonimizados): {len(df)}")
    else:                                   # se arma desde el dataset original
        crudo = pd.read_csv(DATOS / "Phishing_Email.csv")
        df = crudo.rename(columns={"Email Text": "texto", "Email Type": "clase"})
        df = df[["texto", "clase"]]
        n0 = len(df)
        df = df.dropna()                                    # correos vacíos
        df["texto"] = df["texto"].astype(str).str.lower().map(anonimizar)
        df["texto"] = df["texto"].str.replace(r"\s+", " ", regex=True).str.strip()
        df = df[df["texto"].str.len() > 0]
        df = df.drop_duplicates(subset="texto")             # correos repetidos
        print(f"Correos originales: {n0} -> después de limpiar: {len(df)}")
        df[["texto", "clase"]].to_csv(anon, index=False)
    df["y"] = (df["clase"] == "Phishing Email").astype(int)
    print(df["clase"].value_counts().to_string())
    return df


# ------------------------------------------------------------ 2. Piezas reutilizables
def dividir(df):
    """70 % entrenamiento, 15 % validación, 15 % prueba, con la misma
    proporción de cada clase en las tres partes."""
    x_tmp, x_test, y_tmp, y_test = train_test_split(
        df["texto"], df["y"], test_size=0.15, random_state=SEMILLA, stratify=df["y"])
    x_train, x_val, y_train, y_val = train_test_split(
        x_tmp, y_tmp, test_size=0.15 / 0.85, random_state=SEMILLA, stratify=y_tmp)
    return x_train, x_val, x_test, y_train, y_val, y_test


def nuevo_vectorizador():
    """Cada correo se convierte en un vector de números: un peso por palabra
    para las 3.000 palabras más útiles. El peso sube si la palabra se repite
    en el correo y baja si aparece en casi todos (sección 2.4 del TP)."""
    return TfidfVectorizer(max_features=3000, stop_words="english", min_df=3)


def nuevos_modelos():
    return {
        "Red bayesiana": MultinomialNB(),   # P(phishing) · Π P(palabra | phishing)
        "Árbol de decisión": DecisionTreeClassifier(max_depth=12, random_state=SEMILLA),
        "Perceptrón simple": Perceptron(max_iter=50, random_state=SEMILLA),
        "Perceptrón multicapa": MLPClassifier(hidden_layer_sizes=(64,), activation="logistic",
                                              max_iter=30, random_state=SEMILLA),
    }


def guardar_modelo(vect, modelos, carpeta=MODELO):
    """Guarda lo que usa el agente: el vectorizador, el perceptrón multicapa
    (decide) y el árbol (explica)."""
    carpeta.mkdir(exist_ok=True)
    joblib.dump({"vectorizador": vect,
                 "mlp": modelos["Perceptrón multicapa"],
                 "arbol": modelos["Árbol de decisión"]}, carpeta / "detector.joblib", compress=3)


def umbral_en_validacion(p_val, y_val, max_fp=0.01):
    """Elige el umbral con el conjunto de VALIDACIÓN: el más bajo (entre 0,50
    y 0,99) con el que no más del 1 % de los legítimos queda marcado por
    error. Así la prueba no se usa para decidir nada."""
    legitimos = p_val[(y_val == 0).to_numpy()]
    for t in [x / 100 for x in range(50, 100)]:
        if (legitimos >= t).mean() <= max_fp:
            return t
    return 0.99


# ------------------------------------------------------------ 3. Entrenar y evaluar
def main():
    df = cargar()
    x_train, x_val, x_test, y_train, y_val, y_test = dividir(df)
    print(f"Entrenamiento {len(x_train)} · validación {len(x_val)} · prueba {len(x_test)}")

    vect = nuevo_vectorizador()
    v_train = vect.fit_transform(x_train)
    v_val, v_test = vect.transform(x_val), vect.transform(x_test)

    modelos = nuevos_modelos()

    filas, informe = [], []
    fig, ejes = plt.subplots(2, 2, figsize=(10, 8))
    for eje, (nombre, modelo) in zip(ejes.flat, modelos.items()):
        modelo.fit(v_train, y_train)
        acc_val = accuracy_score(y_val, modelo.predict(v_val))
        pred = modelo.predict(v_test)
        cm = confusion_matrix(y_test, pred)
        vn, fp, fn, vp = cm.ravel()
        fila = {
            "Modelo": nombre,
            "Exactitud validación": acc_val,
            "Exactitud prueba": accuracy_score(y_test, pred),
            "Phishing detectado (recall)": recall_score(y_test, pred),
            "Precisión": precision_score(y_test, pred),
            "Legítimos marcados por error": fp / (fp + vn),
            "VP": vp, "FN": fn, "FP": fp, "VN": vn,
        }
        filas.append(fila)
        informe.append(f"=== {nombre} ===\n" + "\n".join(
            f"{k}: {v:.4f}" if isinstance(v, float) else f"{k}: {v}"
            for k, v in fila.items() if k != "Modelo"))
        ConfusionMatrixDisplay(cm, display_labels=["Legítimo", "Phishing"]).plot(
            ax=eje, colorbar=False, cmap="Blues")
        eje.set_xlabel("Lo que dice el modelo"); eje.set_ylabel("Clase real")
        eje.set_title(f"{nombre}\nexactitud {fila['Exactitud prueba']:.1%}".replace(".", ","))
    fig.tight_layout()
    fig.savefig(SALIDA / "matrices_confusion.png", dpi=150)

    tabla = pd.DataFrame(filas)
    tabla.to_csv(SALIDA / "metricas.csv", index=False, float_format="%.4f")

    # Comparación de los cuatro modelos.
    plt.figure(figsize=(10, 4))
    cols = ["Exactitud prueba", "Phishing detectado (recall)", "Precisión"]
    tabla.set_index("Modelo")[cols].plot.bar(ax=plt.gca(), rot=0,
                                             color=["#1f4e79", "#c55a11", "#548235"], figsize=None)
    plt.ylim(0.7, 1.0); plt.ylabel("Proporción (conjunto de prueba)"); plt.xlabel("")
    plt.title("Comparación de los cuatro modelos"); plt.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3, frameon=False)
    plt.grid(axis="y", alpha=0.3); plt.tight_layout()
    plt.savefig(SALIDA / "comparacion_modelos.png", dpi=150)

    # Los dos primeros niveles del árbol: qué palabras mira primero.
    plt.figure(figsize=(14, 6))
    plot_tree(modelos["Árbol de decisión"], max_depth=2,
              feature_names=vect.get_feature_names_out(),
              class_names=["Legítimo", "Phishing"], filled=True, fontsize=8)
    plt.savefig(SALIDA / "arbol_primeros_niveles.png", dpi=150, bbox_inches="tight")

    # Curva de error del perceptrón multicapa (descenso de gradiente).
    mlp = modelos["Perceptrón multicapa"]
    plt.figure(figsize=(6, 4))
    plt.plot(range(1, len(mlp.loss_curve_) + 1), mlp.loss_curve_, marker="o")
    plt.xlabel("Época"); plt.ylabel("Error (función de costo)")
    plt.title("Perceptrón multicapa: el error baja al ajustar los pesos")
    plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(SALIDA / "curva_error_mlp.png", dpi=150)

    # Umbral elegido en validación y medido una sola vez en prueba.
    t = umbral_en_validacion(mlp.predict_proba(v_val)[:, 1], y_val)
    pred_t = (mlp.predict_proba(v_test)[:, 1] >= t).astype(int)
    vn, fp, fn, vp = confusion_matrix(y_test, pred_t).ravel()
    informe.append("=== Perceptrón multicapa con umbral elegido en validación ===\n"
                   f"Umbral: {t:.2f}\n"
                   f"Exactitud prueba: {accuracy_score(y_test, pred_t):.4f}\n"
                   f"Phishing detectado (recall): {vp / (vp + fn):.4f}\n"
                   f"Legítimos marcados por error: {fp / (fp + vn):.4f}\n"
                   f"VP: {vp}\nFN: {fn}\nFP: {fp}\nVN: {vn}")

    guardar_modelo(vect, modelos)
    print("Modelo del agente guardado en modelo/detector.joblib")

    texto = "\n\n".join(informe)
    print(texto)
    (SALIDA / "metricas.txt").write_text(texto + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
