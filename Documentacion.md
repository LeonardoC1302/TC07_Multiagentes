# Documentación del Sistema Multiagente de Ciberseguridad

## Guía de Usuario

### 1. Propósito

Este sistema analiza registros (logs) de seguridad para identificar posibles amenazas cibernéticas, evaluar su gravedad y proporcionar un informe detallado que incluye una alerta, análisis y recomendaciones accionables. Utiliza un equipo de agentes de IA especializados para procesar la información.

### 2. Prerrequisitos

*   **Python 3.7+**
*   **Ollama**: Asegúrate de que Ollama esté instalado y en ejecución.
    *   El sistema está configurado para usar el modelo `llama3.2`. Necesitas descargar este modelo:
        ```bash
        ollama pull llama3.2
        ```
*   **Bibliotecas de Python**: Instala las bibliotecas requeridas. Normalmente puedes hacerlo usando pip:
    ```bash
    pip install langchain langgraph langchain-ollama langchain-huggingface langchain-community sentence-transformers chromadb typing_extensions
    ```
    (Nota: `pandas` se importa en el script pero no se usa activamente en la lógica central mostrada; podría ser para futuras extensiones).

### 3. Cómo Ejecutar el Script

1.  Guarda el código como `main.py` en un directorio (ej., `c:\Users\leona\Documents\IA\TC_Multiagentes\`).
2.  Abre una terminal o símbolo del sistema.
3.  Navega al directorio donde guardaste `main.py`.
4.  Ejecuta el script usando Python:
    ```bash
    python main.py
    ```

### 4. Opciones del Menú

Al ejecutar, verás una descripción general del sistema y los escenarios de amenaza disponibles:

# 🔒 Sistema Multiagente - Analista de Ciberseguridad
Este sistema utiliza 5 agentes especializados:

1. Analizador de Logs: Parsea y categoriza eventos
2. Detector de Amenazas: Identifica tipos de ataques
3. Correlacionador RAG: Consulta patrones conocidos
4. Evaluador de Riesgos: Analiza impacto y severidad
5. Coordinador de Respuesta: Genera alertas y recomendaciones
   ============================================================
Escenarios de amenazas disponibles:

1. Ataque de Fuerza Bruta
2. Inyección SQL
3. Escaneo de Puertos
4. Ataque DDoS
5. Actividad de Malware

Luego se te pedirá que elijas una opción:
============================================================

Elige una opción:
1-5: Analizar escenario de ejemplo (1: Fuerza Bruta, 2: Inyección SQL, 3: Escaneo de Puertos, 4: DDoS, 5: Malware)
'c': Subir logs personalizados para análisis
'q': Salir del programa


*   **`1-5`**: Ingresa un número del 1 al 5 para analizar uno de los escenarios de logs de ejemplo predefinidos.
    *   Ejemplo: Ingresa `1` para "Ataque de Fuerza Bruta".
*   **`c`**: Elige esto para ingresar tus propios logs de seguridad para análisis.
    *   Se te preguntará: `Pega tus logs de seguridad (termina con línea vacía):`
    *   Pega tus líneas de log una por una, o pega un bloque de múltiples líneas.
    *   Presiona Enter después de cada línea.
    *   Presiona Enter en una línea vacía para señalar el final de tu entrada.
*   **`q`**: Ingresa `q` para salir del programa.

### 5. Entendiendo el Informe de Salida

Después de procesar los logs, el sistema imprimirá un informe detallado, estructurado de la siguiente manera:
=== REPORTE DE ANÁLISIS DE SEGURIDAD ===

ALERTA: [ALERTA SEVERITY_LEVEL] THREAT_TYPE DETECTADO
Descripción breve del incidente y acción requerida.
Timestamp: YYYY-MM-DD HH:MM:SS

ANÁLISIS DE AMENAZA:
[Análisis detallado del agente evaluador de riesgos, incluyendo descripción, impacto, vectores, IOCs]

RECOMENDACIONES DE RESPUESTA:
Lista de 3-5 recomendaciones numeradas o con viñetas para contención, mitigación, recuperación y prevención

PATRONES IDENTIFICADOS:
• [Descripción del Patrón 1]
• [Descripción del Patrón 2]
• [Descripción del Patrón 3]

### 6. Guardando el Informe

Después de que se muestre el informe, se te preguntará:
¿Deseas guardar este reporte en un archivo? (s/N):

*   Ingresa `s` (o `S`) y presiona Enter para guardar el informe. Se guardará como `security_report_YYYYMMDD_HHMMSS.txt` en el mismo directorio que el script.
*   Ingresa `n` (o `N`), o simplemente presiona Enter, para no guardar el informe.

---

## Guía del Desarrollador

### 1. Estructura del Código

*   **`main.py`**: El único script que contiene toda la lógica.
    *   **Importaciones**: Bibliotecas necesarias para Langchain, LLMs, embeddings, almacenes vectoriales y utilidades estándar de Python.
    *   **`SecurityState(TypedDict)`**: Define la estructura de datos que se pasa entre agentes en el flujo de trabajo de LangGraph.
    *   **Clase `CybersecurityMultiagent`**:
        *   `__init__`: Inicializa LLM, embeddings, BD vectorial, grafo de agentes y logs de ejemplo.
        *   `setup_threat_database`: Crea o carga el almacén vectorial Chroma con patrones de amenaza predefinidos.
        *   `generate_sample_logs`: Proporciona datos de logs de ejemplo para diferentes escenarios.
        *   `create_agent_graph`: Define el flujo de trabajo de LangGraph, nodos (agentes) y aristas.
        *   **Métodos de Agente**: `log_analyzer_agent`, `threat_detector_agent`, `pattern_matcher_agent`, `risk_assessor_agent`, `response_coordinator_agent`. Cada uno implementa la lógica para un nodo específico en el grafo.
        *   `analyze_logs`: Orquesta una única ejecución del grafo de agentes para datos de logs dados.
    *   **Función `main()`**: Maneja la interacción del usuario (CLI), llama a `CybersecurityMultiagent` para realizar el análisis y muestra los resultados.
    *   **`if __name__ == "__main__":`**: Punto de entrada del script.

### 2. Clases y Estructuras de Datos Clave

*   **`SecurityState`**: Un `TypedDict` que asegura la seguridad de tipos y la claridad de los datos que fluyen a través del grafo de agentes. Cada campo es poblado o utilizado por diferentes agentes.
*   **`langchain.schema.Document`**: Se utiliza para representar patrones de amenaza antes de que se añadan al almacén vectorial.
*   **`langgraph.graph.StateGraph`**: El núcleo del flujo de trabajo del agente.

### 3. Detalles de la Lógica del Agente

*   **`log_analyzer_agent`**:
    *   Utiliza un prompt de LLM para obtener un análisis de texto estructurado de los logs.
    *   Independientemente, utiliza coincidencias de cadenas `if/elif` en `log_data.lower()` para establecer un `threat_type` inicial. La salida estructurada del LLM del prompt no se parsea completamente en el estado en la versión actual.
*   **`threat_detector_agent`**:
    *   Solicita al LLM un nivel de severidad (BAJA, MEDIA, ALTA, CRÍTICA).
    *   Incluye un mecanismo de respaldo: si la salida del LLM no es una de las severidades válidas, asigna una basada en mapeos predefinidos para `threat_type`.
*   **`pattern_matcher_agent`**:
    *   Realiza una búsqueda de similitud en el almacén vectorial `Chroma`.
    *   La consulta se construye a partir de `state['threat_type']` y `state['severity_level']`.
    *   Recupera `k=3` patrones más relevantes.
*   **`risk_assessor_agent`**:
    *   Solicita al LLM con la información de amenaza actual y los patrones coincidentes que genere un análisis textual detallado.
*   **`response_coordinator_agent`**:
    *   Realiza dos llamadas al LLM: una para recomendaciones y otra para un mensaje de alerta.
    *   Parsea las recomendaciones (líneas que comienzan con dígito, '-', o '•').
    *   Construye la cadena `final_report`.
        *   **Nota de Error**: En la construcción de la cadena `final_report`, `RECOMENDACIONES DE RESPUESTA:` es seguido por `"\n".join(state['attack_patterns'])` en lugar de `"\n".join(state['recommendations'])`. Esto debería corregirse para mostrar las recomendaciones generadas.

### 4. Base de Datos Vectorial (`setup_threat_database`)

*   Se utiliza una lista predefinida de `threat_patterns` (cadenas) como base de conocimiento.
*   Se utiliza `RecursiveCharacterTextSplitter` para fragmentar estos patrones.
*   `Chroma.from_documents` crea el almacén vectorial si no existe o no se puede cargar.
*   La base de datos se persiste en el directorio `./threat_db`.
*   La implementación ahora incluye lógica para intentar cargar una base de datos existente desde `persist_directory` antes de recrearla.

### 5. Flujo de Trabajo LangGraph (`create_agent_graph`)

*   Se inicializa un `StateGraph` con `SecurityState`.
*   Cada método de agente se añade como un nodo.
*   `set_entry_point("log_analyzer")` define el inicio del flujo de trabajo.
*   `add_edge` define la secuencia lineal de ejecución de los agentes.
*   El grafo se compila con `MemorySaver` para puntos de control, permitiendo la persistencia y reanudación potencial del estado (aunque no se usa explícitamente para la reanudación en el flujo CLI actual).

### 6. Configuración

*   **Modelo LLM**: Codificado como `llama3.2` en `OllamaLLM(model="llama3.2", ...)`.
*   **URL Base de Ollama**: Codificada como `http://localhost:11434`.
*   **Modelo de Embedding**: Codificado como `sentence-transformers/all-MiniLM-L6-v2`.
*   **Ruta del Almacén Vectorial**: Codificada como `./threat_db`.
*   **Mejora Futura**: Estos podrían moverse a un archivo de configuración (ej., JSON, YAML, .env) o variables de entorno para una gestión más fácil.

### 7. Dependencias

Asegúrate de que estén instaladas (ver Prerrequisitos de la Guía de Usuario):
*   `langchain`
*   `langgraph`
*   `langchain_ollama`
*   `langchain_huggingface`
*   `langchain_community`
*   `sentence-transformers`
*   `chromadb`
*   `typing_extensions` (a menudo una dependencia de los componentes de Langchain)
*   `pandas` (importado pero no utilizado directamente en el flujo principal)

### 8. Mejoras Potenciales / Áreas de Oportunidad

*   **Parseo de Logs Refinado**: El `log_analyzer_agent` podría parsear más profundamente la salida estructurada del LLM (EVENTOS, ACTORES, PATRONES) y almacenar estos detalles en `SecurityState` para un contexto más rico para los agentes subsecuentes.
*   **Manejo de Errores**: Manejo de errores más granular dentro de cada agente y para llamadas LLM/API.
*   **Enrutamiento Dinámico de Agentes**: Para escenarios más complejos, se podrían usar aristas condicionales en LangGraph para enrutar a diferentes agentes basados en hallazgos intermedios.
*   **Expansión de la Base de Conocimiento**: Permitir a los usuarios añadir/actualizar patrones de amenaza en el almacén vectorial.
*   **Formato del Informe**: Mejorar la estructura del informe final u ofrecer diferentes formatos de salida (ej., JSON, HTML).
*   **Corregir Error del Informe**: Corregir el error en `response_coordinator_agent` donde se muestran `attack_patterns` en lugar de `recommendations` en el informe final.
*   **Gestión de Configuración**: Externalizar nombres de modelos, URLs y rutas codificadas.
*   **Pruebas**: Implementar pruebas unitarias y de integración para los agentes y el flujo de trabajo general.
