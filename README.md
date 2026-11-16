# Detección de phishing con IA — prototipo

Trabajo práctico final de **Inteligencia Artificial (0246)**, Universidad de Palermo, 2do cuatrimestre 2026.
Grupo 10: Alan Bazarian, Elias Joshua Caero, Ignacio Pacheco, Mateo Valenzuela y Valentino Albarian.

El prototipo entrena cuatro modelos vistos en la materia sobre el mismo conjunto público de correos etiquetados (aprendizaje supervisado) y compara cuánto acierta cada uno:

1. **Red bayesiana**: el nodo «phishing» influye sobre cada palabra; las palabras se suponen independientes entre sí dada la clase.
2. **Árbol de decisión** aprendido de los ejemplos, limitado a 12 niveles.
3. **Perceptrón simple**.
4. **Perceptrón multicapa**: 64 neuronas ocultas, activación sigmoidea, entrenado con backpropagation y descenso de gradiente.

## Resultados (conjunto de prueba: 2.616 correos)

| Modelo | Exactitud | Phishing detectado | Legítimos marcados por error |
|---|---|---|---|
| Red bayesiana | 95,9 % | 93,2 % | 2,6 % |
| Árbol de decisión (12 niveles) | 85,1 % | 94,3 % | 20,4 % |
| Perceptrón simple | 96,2 % | 94,8 % | 3,0 % |
| Perceptrón multicapa (64 neuronas) | **97,4 %** | **96,9 %** | **2,3 %** |

Matrices de confusión, árbol y curva de error en `resultados/`.

## Datos

`datos/correos_anonimizados.csv`: 17.437 correos (10.966 legítimos, 6.471 phishing) del *Phishing Email Dataset* (Kaggle; copia en https://huggingface.co/datasets/zefang-liu/phishing-email-dataset), sin vacíos ni duplicados y con direcciones de correo, enlaces y números largos reemplazados por `<EMAIL>`, `<URL>` y `<NUM>`.

División estratificada: 70 % entrenamiento, 15 % validación, 15 % prueba (semilla 42).

## Cómo ejecutarlo

```
pip install -r requirements.txt
python phishing_ia.py
```

Tarda alrededor de un minuto en una PC común y reproduce exactamente los números de la tabla.
