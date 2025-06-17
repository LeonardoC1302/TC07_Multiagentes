import os
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, TypedDict
from langchain_ollama import OllamaLLM
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
import chromadb

class SecurityState(TypedDict):
    log_data: str
    threat_type: str
    severity_level: str
    attack_patterns: List[str]
    threat_analysis: str # Corrected typo: str111 -> str
    recommendations: List[str]
    alert_message: str
    final_report: str

class CybersecurityMultiagent:
    def __init__(self):
        # Inicializar LLM con Ollama
        # Updated class name for Ollama
        self.llm = OllamaLLM(model="llama3.2", base_url="http://localhost:11434")

        # Inicializar embeddings
        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )

        # Configurar base vectorial con patrones de amenazas
        self.setup_threat_database()

        # Crear el grafo de agentes
        self.create_agent_graph()

        # Generar logs de ejemplo
        self.generate_sample_logs()

    def setup_threat_database(self):
        """Configura la base de datos vectorial con patrones de amenazas conocidos"""

        persist_directory = "./threat_db"

        # Base de conocimiento de amenazas de ciberseguridad
        threat_patterns = [
            "Brute Force Attack: Múltiples intentos de login fallidos desde la misma IP en corto período. Patrón: >10 fallos en 5 minutos. Severidad: Media-Alta.",
            "SQL Injection: Caracteres especiales en parámetros web como ', --, UNION, SELECT. Patrón: Comillas simples, comentarios SQL, comandos UNION. Severidad: Alta.",
            "Cross-Site Scripting XSS: Scripts maliciosos en campos de entrada web. Patrón: <script>, javascript:, onload=, onerror=. Severidad: Media.",
            "Port Scanning: Múltiples conexiones a diferentes puertos desde una IP. Patrón: >20 puertos diferentes en 10 minutos. Severidad: Media.",
            "DDoS Attack: Volumen anormalmente alto de requests desde múltiples IPs. Patrón: >1000 requests/minuto, múltiples fuentes. Severidad: Alta.",
            "Malware Communication: Conexiones a dominios o IPs conocidos como maliciosos. Patrón: C&C servers, dominios generados algorítmicamente. Severidad: Crítica.",
            "Privilege Escalation: Acceso a recursos con permisos elevados sin autorización. Patrón: sudo fallido, acceso admin inesperado. Severidad: Alta.",
            "Data Exfiltration: Transferencia inusual de grandes volúmenes de datos. Patrón: Uploads masivos, acceso a archivos sensibles. Severidad: Crítica.",
            "Phishing Attack: Enlaces sospechosos o dominios que imitan sitios legítimos. Patrón: Dominios similares, URLs acortadas maliciosas. Severidad: Media.",
            "Ransomware Activity: Encriptación masiva de archivos o extensiones sospechosas. Patrón: .encrypted, .locked, notas de rescate. Severidad: Crítica.",
            "Insider Threat: Acceso fuera de horario laboral o patrones inusuales de usuario legítimo. Patrón: Acceso nocturno, descargas masivas. Severidad: Media-Alta.",
            "Man-in-the-Middle: Certificados SSL inválidos o conexiones no seguras. Patrón: Cert warnings, HTTP en lugar de HTTPS. Severidad: Alta.",
            "Backdoor Access: Conexiones entrantes en puertos no estándar o servicios desconocidos. Patrón: Puertos altos, servicios no autorizados. Severidad: Alta.",
            "Zero-Day Exploit: Comportamiento anómalo en aplicaciones sin patrones conocidos. Patrón: Crashes inesperados, ejecución código arbitrario. Severidad: Crítica.",
            "DNS Tunneling: Queries DNS inusuales con payloads grandes o patrones extraños. Patrón: Subdominios largos, queries frecuentes. Severidad: Media-Alta."
        ]

        # Crear documentos
        docs = [Document(page_content=pattern, metadata={"category": "threat_pattern"}) for pattern in threat_patterns]

        # Dividir texto
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=300, chunk_overlap=50)
        split_docs = text_splitter.split_documents(docs)

        # Crear o cargar base vectorial
        try:
            if os.path.exists(persist_directory) and os.listdir(persist_directory):
                print("Cargando base de datos de amenazas existente...")
                self.vectorstore = Chroma(
                    persist_directory=persist_directory,
                    embedding_function=self.embeddings
                )
                # Perform a quick check to ensure it's usable
                self.vectorstore.similarity_search("test", k=1)
                print("Base de datos cargada exitosamente.")
            else:
                raise FileNotFoundError # Trigger creation
        except Exception as e:
            print(f"No se pudo cargar la base de datos existente o está vacía/corrupta ({e}), creando una nueva...")
            if not os.path.exists(persist_directory):
                os.makedirs(persist_directory)
            self.vectorstore = Chroma.from_documents(
                documents=split_docs,
                embedding=self.embeddings,
                persist_directory=persist_directory
            )
            print("Nueva base de datos de amenazas creada y persistida.")

    def generate_sample_logs(self):
        """Genera logs de ejemplo para demostración"""
        self.sample_logs = {
            "brute_force": """
2025-06-10 14:23:15 [AUTH] FAILED login attempt for user 'admin' from 192.168.1.100
2025-06-10 14:23:17 [AUTH] FAILED login attempt for user 'admin' from 192.168.1.100
2025-06-10 14:23:19 [AUTH] FAILED login attempt for user 'admin' from 192.168.1.100
2025-06-10 14:23:21 [AUTH] FAILED login attempt for user 'root' from 192.168.1.100
2025-06-10 14:23:23 [AUTH] FAILED login attempt for user 'administrator' from 192.168.1.100
2025-06-10 14:23:25 [AUTH] FAILED login attempt for user 'admin' from 192.168.1.100
2025-06-10 14:23:27 [AUTH] FAILED login attempt for user 'admin' from 192.168.1.100
2025-06-10 14:23:29 [AUTH] FAILED login attempt for user 'admin' from 192.168.1.100
2025-06-10 14:23:31 [AUTH] FAILED login attempt for user 'admin' from 192.168.1.100
2025-06-10 14:23:33 [AUTH] FAILED login attempt for user 'admin' from 192.168.1.100
2025-06-10 14:23:35 [AUTH] FAILED login attempt for user 'admin' from 192.168.1.100
2025-06-10 14:23:37 [AUTH] FAILED login attempt for user 'admin' from 192.168.1.100
""",
            "sql_injection": """
2025-06-10 15:45:22 [WEB] GET /login.php?user=admin'%20OR%201=1--&pass=test from 203.0.113.45
2025-06-10 15:45:25 [WEB] POST /search.php data: query='; DROP TABLE users;-- from 203.0.113.45
2025-06-10 15:45:28 [WEB] GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20admin from 203.0.113.45
2025-06-10 15:45:31 [DB] ERROR: SQL syntax error near 'DROP TABLE users'
2025-06-10 15:45:33 [WEB] GET /admin.php?user=admin'%20AND%201=1-- from 203.0.113.45
""",
            "port_scan": """
2025-06-10 16:12:03 [FIREWALL] Connection attempt to port 22 from 198.51.100.15 - BLOCKED
2025-06-10 16:12:04 [FIREWALL] Connection attempt to port 23 from 198.51.100.15 - BLOCKED
2025-06-10 16:12:05 [FIREWALL] Connection attempt to port 25 from 198.51.100.15 - BLOCKED
2025-06-10 16:12:06 [FIREWALL] Connection attempt to port 53 from 198.51.100.15 - BLOCKED
2025-06-10 16:12:07 [FIREWALL] Connection attempt to port 80 from 198.51.100.15 - ALLOWED
2025-06-10 16:12:08 [FIREWALL] Connection attempt to port 110 from 198.51.100.15 - BLOCKED
2025-06-10 16:12:09 [FIREWALL] Connection attempt to port 443 from 198.51.100.15 - ALLOWED
2025-06-10 16:12:10 [FIREWALL] Connection attempt to port 993 from 198.51.100.15 - BLOCKED
2025-06-10 16:12:11 [FIREWALL] Connection attempt to port 995 from 198.51.100.15 - BLOCKED
2025-06-10 16:12:12 [FIREWALL] Connection attempt to port 3389 from 198.51.100.15 - BLOCKED
""",
            "ddos": """
2025-06-10 17:30:15 [WEB] 200 GET / from 192.0.2.10 - 0.02s
2025-06-10 17:30:15 [WEB] 200 GET / from 192.0.2.11 - 0.03s
2025-06-10 17:30:15 [WEB] 200 GET / from 192.0.2.12 - 0.02s
2025-06-10 17:30:15 [WEB] 200 GET / from 192.0.2.13 - 0.04s
[... 500 more similar requests in 30 seconds ...]
2025-06-10 17:30:45 [SYSTEM] High CPU usage detected: 95%
2025-06-10 17:30:46 [SYSTEM] Memory usage critical: 98%
2025-06-10 17:30:47 [WEB] Server response time degraded: 5.2s average
""",
            "malware": """
2025-06-10 18:15:23 [DNS] Query: malicious-c2-server.darkweb.onion from 10.0.0.50
2025-06-10 18:15:25 [NETWORK] Outbound connection to 185.220.101.5:8080 from 10.0.0.50
2025-06-10 18:15:27 [PROCESS] Suspicious executable: ransomware.exe started on 10.0.0.50
2025-06-10 18:15:30 [FILE] Mass file encryption detected on 10.0.0.50
2025-06-10 18:15:32 [FILE] Created: README_DECRYPT.txt on Desktop
2025-06-10 18:15:35 [NETWORK] Data exfiltration attempt: 2.5GB uploaded to unknown server
"""
        }

    def create_agent_graph(self):
        """Crea el grafo de agentes especializados"""

        workflow = StateGraph(SecurityState)

        # Agregar agentes especializados
        workflow.add_node("log_analyzer", self.log_analyzer_agent)
        workflow.add_node("threat_detector", self.threat_detector_agent)
        workflow.add_node("pattern_matcher", self.pattern_matcher_agent)
        workflow.add_node("risk_assessor", self.risk_assessor_agent)
        workflow.add_node("response_coordinator", self.response_coordinator_agent)

        # Definir flujo de trabajo
        workflow.set_entry_point("log_analyzer")
        workflow.add_edge("log_analyzer", "threat_detector")
        workflow.add_edge("threat_detector", "pattern_matcher")
        workflow.add_edge("pattern_matcher", "risk_assessor")
        workflow.add_edge("risk_assessor", "response_coordinator")
        workflow.add_edge("response_coordinator", END)

        # Compilar grafo
        memory = MemorySaver()
        self.graph = workflow.compile(checkpointer=memory)

    def log_analyzer_agent(self, state: SecurityState) -> SecurityState:
        """Agente que analiza y parsea logs de seguridad"""

        prompt = f"""
        Eres un agente analizador de logs de seguridad especializados.

        Analiza los siguientes logs:
        {state['log_data']}

        Identifica:
        1. Tipos de eventos de seguridad presentes
        2. IPs o usuarios involucrados
        3. Patrones temporales sospechosos
        4. Frecuencia de eventos

        Responde en formato:
        EVENTOS: [tipos de eventos encontrados]
        ACTORES: [IPs, usuarios, etc.]
        PATRONES: [patrones temporales o de frecuencia]
        """

        analysis = self.llm.invoke(prompt)

        # Extraer tipo de amenaza básico de los logs
        log_lower = state['log_data'].lower()
        if 'failed login' in log_lower and log_lower.count('failed') > 5:
            threat_type = "Brute Force Attack"
        elif 'union select' in log_lower or 'drop table' in log_lower or "'" in log_lower:
            threat_type = "SQL Injection"
        elif 'connection attempt' in log_lower and log_lower.count('port') > 5:
            threat_type = "Port Scanning"
        elif log_lower.count('get /') > 20:
            threat_type = "DDoS Attack"
        elif 'malicious' in log_lower or 'ransomware' in log_lower:
            threat_type = "Malware Activity"
        else:
            threat_type = "Unknown Threat"

        state['threat_type'] = threat_type
        return state

    def threat_detector_agent(self, state: SecurityState) -> SecurityState:
        """Agente especializado en detección de amenazas"""

        prompt = f"""
        Eres un agente detector de amenazas de ciberseguridad.

        Tipo de amenaza identificada: {state['threat_type']}
        Logs analizados: {state['log_data'][:500]}...

        Evalúa la severidad de esta amenaza:
        - BAJA: Actividad sospechosa menor
        - MEDIA: Amenaza potencial que requiere monitoreo
        - ALTA: Amenaza activa que requiere acción inmediata
        - CRÍTICA: Compromiso confirmado o inminente

        Considera factores como frecuencia, impacto potencial, y evidencia de compromiso.

        Responde solo: BAJA, MEDIA, ALTA, o CRÍTICA
        """

        severity = self.llm.invoke(prompt).strip().upper()

        # Validar respuesta
        valid_severities = ["BAJA", "MEDIA", "ALTA", "CRÍTICA"]
        if severity not in valid_severities:
            # Determinar severidad basada en tipo de amenaza
            critical_threats = ["Malware Activity", "Data Exfiltration", "Ransomware"]
            high_threats = ["SQL Injection", "DDoS Attack", "Privilege Escalation"]
            medium_threats = ["Brute Force Attack", "Port Scanning", "XSS"]

            if state['threat_type'] in critical_threats:
                severity = "CRÍTICA"
            elif state['threat_type'] in high_threats:
                severity = "ALTA"
            elif state['threat_type'] in medium_threats:
                severity = "MEDIA"
            else:
                severity = "BAJA"

        state['severity_level'] = severity
        return state

    def pattern_matcher_agent(self, state: SecurityState) -> SecurityState:
        """Agente RAG que consulta patrones conocidos de amenazas"""

        # Buscar patrones relacionados en la base de conocimiento
        query = f"{state['threat_type']} {state['severity_level']} cybersecurity threat pattern"
        relevant_patterns = self.vectorstore.similarity_search(query, k=3)

        attack_patterns = [doc.page_content for doc in relevant_patterns]
        state['attack_patterns'] = attack_patterns

        return state

    def risk_assessor_agent(self, state: SecurityState) -> SecurityState:
        """Agente que evalúa riesgos y genera análisis detallado"""

        patterns_text = "\n".join(state['attack_patterns'])

        prompt = f"""
        Eres un agente evaluador de riesgos de ciberseguridad.

        Información del incidente:
        - Tipo de amenaza: {state['threat_type']}
        - Nivel de severidad: {state['severity_level']}
        - Patrones conocidos encontrados:
        {patterns_text}

        Genera un análisis detallado que incluya:
        1. Descripción del ataque y sus características
        2. Impacto potencial en la organización
        3. Vectores de ataque utilizados
        4. Indicadores de compromiso (IOCs)

        Mantén un tono profesional y técnico.
        """

        threat_analysis = self.llm.invoke(prompt)
        state['threat_analysis'] = threat_analysis

        return state

    def response_coordinator_agent(self, state: SecurityState) -> SecurityState:
        """Agente coordinador que genera recomendaciones y alertas"""

        prompt_recommendations = f"""
        Eres un agente coordinador de respuesta a incidentes de seguridad.

        Incidente: {state['threat_type']} - Severidad: {state['severity_level']}

        Genera 3-5 recomendaciones específicas de respuesta inmediata:
        - Acciones de contención
        - Medidas de mitigación
        - Pasos de recuperación
        - Mejoras preventivas

        Formato: Lista numerada con acciones concretas.
        """

        recommendations_text = self.llm.invoke(prompt_recommendations)

        # Procesar recomendaciones
        recommendations = []
        lines = recommendations_text.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('-') or line.startswith('•')):
                recommendations.append(line)

        state['recommendations'] = recommendations

        # Generar alerta
        alert_prompt = f"""
        Genera una alerta de seguridad concisa para {state['threat_type']} con severidad {state['severity_level']}.

        Formato:
        [ALERTA {state['severity_level']}] {state['threat_type']} DETECTADO
        Descripción breve del incidente y acción requerida.
        Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """

        alert_message = self.llm.invoke(alert_prompt)
        state['alert_message'] = alert_message

        # Generar reporte final
        final_report = f"""
        === REPORTE DE ANÁLISIS DE SEGURIDAD ===

        ALERTA: {state['alert_message']}

        ANÁLISIS DE AMENAZA:
        {state['threat_analysis']}

        RECOMENDACIONES DE RESPUESTA:
        """ + "\n".join(state['attack_patterns'])

        state['final_report'] = final_report

        return state

    def analyze_logs(self, log_data: str) -> str:
        """Analiza logs y genera reporte de seguridad"""

        initial_state = SecurityState(
            log_data=log_data,
            threat_type="",
            severity_level="",
            attack_patterns=[],
            threat_analysis="",
            recommendations=[],
            alert_message="",
            final_report=""
        )

        # Ejecutar análisis multiagente
        config = {"configurable": {"thread_id": f"security_analysis_{datetime.now().timestamp()}"}}
        result = self.graph.invoke(initial_state, config)

        return result['final_report']

def main():
    """Función principal para demostrar el sistema"""

    print("🔒 Sistema Multiagente - Analista de Ciberseguridad")
    print("=" * 60)
    print("Este sistema utiliza 5 agentes especializados:")
    print("1. Analizador de Logs: Parsea y categoriza eventos")
    print("2. Detector de Amenazas: Identifica tipos de ataques")
    print("3. Correlacionador RAG: Consulta patrones conocidos")
    print("4. Evaluador de Riesgos: Analiza impacto y severidad")
    print("5. Coordinador de Respuesta: Genera alertas y recomendaciones")
    print("=" * 60)

    # Inicializar sistema
    analyzer = CybersecurityMultiagent()

    # Mostrar escenarios disponibles
    scenarios = {
        "1": ("Ataque de Fuerza Bruta", "brute_force"),
        "2": ("Inyección SQL", "sql_injection"),
        "3": ("Escaneo de Puertos", "port_scan"),
        "4": ("Ataque DDoS", "ddos"),
        "5": ("Actividad de Malware", "malware")
    }

    print("\nEscenarios de amenazas disponibles:")
    for key, (name, _) in scenarios.items():
        print(f"{key}. {name}")

    while True:
        print("\n" + "="*60)
        choice = input("\nElige una opción:\n"
                       "1-5: Analizar escenario de ejemplo (1: Fuerza Bruta, 2: Inyección SQL, 3: Escaneo de Puertos, 4: DDoS, 5: Malware)\n"
                       "'c': Subir logs personalizados para análisis\n"
                       "'q': Salir del programa\n"
                       "> ")

        if choice.lower() == 'q':
            break
        elif choice.lower() == 'c':
            print("\nPega tus logs de seguridad (termina con línea vacía):")
            logs = []
            while True:
                line = input()
                if not line:
                    break
                logs.append(line)
            log_data = "\n".join(logs)
        elif choice in scenarios:
            scenario_name, scenario_key = scenarios[choice]
            log_data = analyzer.sample_logs[scenario_key]
            print(f"\nAnalizando escenario: {scenario_name}")
        else:
            print("Opción no válida")
            continue

        if not log_data.strip():
            print("No se proporcionaron logs para analizar")
            continue

        print(f"\nEjecutando análisis multiagente...")
        print("Procesando logs...")

        try:
            report = analyzer.analyze_logs(log_data)
            print(f"\n{report}")

            save_report = input("\n¿Deseas guardar este reporte en un archivo? (s/N): ").lower()
            if save_report == 's':
                report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(report_filename, "w", encoding="utf-8") as f:
                    f.write(report)
                print(f"Reporte guardado como: {report_filename}")
        except Exception as e:
            print(f"\nError durante el análisis: {e}")
            print("Asegúrate de que Ollama esté ejecutándose con el modelo llama3.2")

if __name__ == "__main__":
    main()
