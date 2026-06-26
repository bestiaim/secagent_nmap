#!/usr/bin/env python3
"""
secagentV3.py - Agente de reconocimiento con Nmap + Ollama.

Estructura:
    Usuario -> Nmap escanea todos los puertos -> Python clasifica servicios -> LLM analiza según la solicitud

Uso:
    python secagentV4_nmap.py "Verifica los servicios web de 10.10.1.129"
    python secagentV4_nmap.py "Analiza servicios de bases de datos en 10.10.1.129"
    python secagentV4_nmap.py "Realiza un análisis completo de 10.10.1.129"
    python secagentV3.py
"""

import sys
import re
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
import ollama


# ============================================================
# CONFIGURACIÓN
# ============================================================

# Debe coincidir exactamente con lo que muestra:
# ollama list
#
# Puedes usar:
# MODEL = "llama3.2:latest"
# MODEL = "dolphincoder:latest"
# MODEL = "dolphin-mistral:latest"
MODEL = "dolphin-mistral:latest"

# Mostrar JSON técnico solo para depuración
SHOW_JSON = False

# Activar análisis del LLM
USE_LLM_ANALYSIS = True

# Timeout máximo para Nmap en segundos.
# Escanear todos los puertos puede demorar.
NMAP_TIMEOUT = 1800

# Argumentos base de Nmap.
# -p-        = todos los puertos TCP
# -sV        = detección de versión/servicio
# --open     = muestra solo puertos abiertos
# -T4        = velocidad razonable en laboratorio
# -oX -      = salida XML por stdout para que Python la procese
NMAP_ARGS = ["nmap", "-p-", "-sV", "--open", "-T4", "-oX", "-"]  #### podemos modificar 


# ============================================================
# CATEGORÍAS DE SERVICIOS
# ============================================================

CATEGORY_RULES = {
    "web": {
        "ports": {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443},
        "services": {
            "http", "https", "http-alt", "https-alt", "ssl/http",
            "http-proxy", "http-mgmt"
        },
        "keywords": {
            "apache", "nginx", "tomcat", "jetty", "iis", "httpd",
            "web", "proxy", "http"
        }
    },

    "db": {
        "ports": {1433, 1521, 3306, 5432, 6379, 27017, 27018, 9200, 9300, 9042},
        "services": {
            "mysql", "postgresql", "ms-sql-s", "oracle", "redis",
            "mongodb", "elasticsearch", "cassandra"
        },
        "keywords": {
            "mysql", "mariadb", "postgres", "mssql", "sql server",
            "oracle", "redis", "mongo", "elasticsearch", "database"
        }
    },

    "remote": {
        "ports": {22, 23, 3389, 5900, 5901, 5985, 5986},
        "services": {
            "ssh", "telnet", "ms-wbt-server", "vnc", "winrm", "wsman"
        },
        "keywords": {
            "ssh", "telnet", "rdp", "remote desktop", "vnc", "winrm", "wsman"
        }
    },

    "smb": {
        "ports": {139, 445},
        "services": {
            "netbios-ssn", "microsoft-ds", "smb"
        },
        "keywords": {
            "smb", "netbios", "microsoft-ds", "samba", "windows file sharing"
        }
    },

    "mail": {
        "ports": {25, 110, 143, 465, 587, 993, 995},
        "services": {
            "smtp", "pop3", "imap", "smtps", "submission", "imaps", "pop3s"
        },
        "keywords": {
            "smtp", "mail", "postfix", "exim", "dovecot", "imap", "pop3"
        }
    },

    "dns": {
        "ports": {53},
        "services": {
            "domain", "dns"
        },
        "keywords": {
            "dns", "bind", "domain"
        }
    },

    "ftp": {
        "ports": {20, 21},
        "services": {
            "ftp", "ftp-data"
        },
        "keywords": {
            "ftp", "vsftpd", "proftpd", "filezilla"
        }
    },

    "admin": {
        "ports": {
            21, 22, 23, 80, 443, 445, 3306, 3389,
            5432, 5900, 5985, 5986, 8000, 8080, 8081, 8443, 8888, 9200
        },
        "services": {
            "ssh", "telnet", "ftp", "http", "https", "http-alt",
            "microsoft-ds", "mysql", "postgresql", "ms-wbt-server",
            "vnc", "winrm", "elasticsearch"
        },
        "keywords": {
            "admin", "management", "console", "dashboard", "panel",
            "ssh", "rdp", "vnc", "winrm", "mysql", "postgres",
            "smb", "phpmyadmin", "tomcat", "jenkins"
        }
    },
}


CATEGORY_LABELS = {
    "web": "Servicios web",
    "db": "Bases de datos",
    "remote": "Administración remota",
    "smb": "SMB / compartición de archivos",
    "mail": "Correo",
    "dns": "DNS",
    "ftp": "FTP",
    "admin": "Servicios administrativos o sensibles",
    "complete": "Análisis completo",
}


# ============================================================
# VALIDACIÓN Y DETECCIÓN DE INTENCIÓN
# ============================================================

def extract_ip_from_text(text: str) -> str | None:
    """
    Extrae una IPv4 desde el texto del usuario.
    """

    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)

    if not match:
        return None

    ip = match.group(0)
    parts = ip.split(".")

    for part in parts:
        if int(part) < 0 or int(part) > 255:
            return None

    return ip


def detect_analysis_category(text: str) -> str:
    """
    Detecta qué tipo de análisis quiere el usuario.
    Nmap siempre escanea todos los puertos.
    Esta categoría solo define qué resultados se priorizan en el análisis.
    """

    text = text.lower()

    if (
        "completo" in text
        or "completa" in text
        or "general" in text
        or "todo" in text
        or "todos" in text
        or "sin importar" in text
        or "toda la superficie" in text
    ):
        return "complete"

    if (
        "web" in text
        or "http" in text
        or "https" in text
        or "pagina" in text
        or "página" in text
        or "sitio" in text
        or "aplicacion web" in text
        or "aplicación web" in text
    ):
        return "web"

    if (
        "base de datos" in text
        or "bases de datos" in text
        or "database" in text
        or "db" in text
        or "mysql" in text
        or "postgres" in text
        or "mssql" in text
        or "oracle" in text
        or "redis" in text
        or "mongo" in text
        or "elasticsearch" in text
    ):
        return "db"

    if (
        "administrativo" in text
        or "administrativos" in text
        or "administracion" in text
        or "administración" in text
        or "gestion" in text
        or "gestión" in text
        or "management" in text
        or "panel" in text
        or "consola" in text
    ):
        return "admin"

    if (
        "remoto" in text
        or "remotos" in text
        or "remote" in text
        or "ssh" in text
        or "rdp" in text
        or "vnc" in text
        or "winrm" in text
    ):
        return "remote"

    if "smb" in text or "netbios" in text or "445" in text or "compartidos" in text:
        return "smb"

    if (
        "correo" in text
        or "mail" in text
        or "smtp" in text
        or "imap" in text
        or "pop3" in text
    ):
        return "mail"

    if "dns" in text or "dominio" in text:
        return "dns"

    if "ftp" in text:
        return "ftp"

    return "complete"


# ============================================================
# EJECUCIÓN DE NMAP
# ============================================================

def ensure_nmap_installed():
    """
    Verifica que Nmap esté instalado.
    """

    if shutil.which("nmap") is None:
        print("[!] Nmap no está instalado o no está en el PATH.")
        print("Instala con:")
        print("  sudo apt update")
        print("  sudo apt install nmap")
        sys.exit(1)


def run_nmap_full_scan(ip: str) -> dict:
    """
    Ejecuta Nmap contra todos los puertos TCP y devuelve resultado parseado.
    """

    ensure_nmap_installed()

    cmd = NMAP_ARGS + [ip]

    print("")
    print("=== EJECUTANDO NMAP ===")
    print("Comando:")
    print(" ".join(cmd))
    print("")
    print("[*] Escaneando todos los puertos TCP. Esto puede demorar...")

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT
        )

    except subprocess.TimeoutExpired:
        return {
            "ip": ip,
            "error": f"Nmap superó el timeout de {NMAP_TIMEOUT} segundos.",
            "open_ports": []
        }

    if completed.returncode not in [0, 1]:
        return {
            "ip": ip,
            "error": completed.stderr.strip() or "Nmap terminó con error.",
            "open_ports": []
        }

    xml_output = completed.stdout

    if not xml_output.strip():
        return {
            "ip": ip,
            "error": "Nmap no devolvió salida XML.",
            "open_ports": []
        }

    return parse_nmap_xml(ip, xml_output)


def parse_nmap_xml(ip: str, xml_output: str) -> dict:
    """
    Parsea la salida XML de Nmap.
    """

    open_ports = []

    try:
        root = ET.fromstring(xml_output)

    except ET.ParseError as e:
        return {
            "ip": ip,
            "error": f"No se pudo parsear XML de Nmap: {e}",
            "open_ports": []
        }

    host = root.find("host")

    if host is None:
        return {
            "ip": ip,
            "host_status": "unknown",
            "open_ports": []
        }

    status_element = host.find("status")
    host_status = status_element.attrib.get("state", "unknown") if status_element is not None else "unknown"

    ports_element = host.find("ports")

    if ports_element is not None:
        for port_element in ports_element.findall("port"):
            protocol = port_element.attrib.get("protocol", "tcp")
            port_id = int(port_element.attrib.get("portid", 0))

            state_element = port_element.find("state")
            state = state_element.attrib.get("state", "unknown") if state_element is not None else "unknown"

            if state != "open":
                continue

            service_element = port_element.find("service")

            service_name = ""
            product = ""
            version = ""
            extrainfo = ""
            tunnel = ""

            if service_element is not None:
                service_name = service_element.attrib.get("name", "")
                product = service_element.attrib.get("product", "")
                version = service_element.attrib.get("version", "")
                extrainfo = service_element.attrib.get("extrainfo", "")
                tunnel = service_element.attrib.get("tunnel", "")

            open_ports.append({
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": service_name or "unknown",
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "tunnel": tunnel,
                "categories": classify_service(
                    port_id,
                    service_name,
                    product,
                    version,
                    extrainfo,
                    tunnel
                )
            })

    return {
        "ip": ip,
        "host_status": host_status,
        "scanner": "nmap",
        "scan_type": "all_tcp_ports_with_service_detection",
        "open_count": len(open_ports),
        "open_ports": sorted(open_ports, key=lambda x: x["port"])
    }


# ============================================================
# CLASIFICACIÓN DE SERVICIOS
# ============================================================

def classify_service(port: int, service: str, product: str, version: str, extrainfo: str, tunnel: str) -> list[str]:
    """
    Clasifica un puerto abierto en categorías.
    """

    service_text = f"{service} {product} {version} {extrainfo} {tunnel}".lower()
    categories = []

    for category, rules in CATEGORY_RULES.items():
        port_match = port in rules["ports"]

        service_match = service.lower() in rules["services"] if service else False

        keyword_match = any(keyword in service_text for keyword in rules["keywords"])

        if port_match or service_match or keyword_match:
            categories.append(category)

    if not categories:
        categories.append("other")

    return sorted(set(categories))


def filter_services_by_category(scan_result: dict, category: str) -> list[dict]:
    """
    Filtra puertos abiertos según la categoría solicitada.
    """

    open_ports = scan_result.get("open_ports", [])

    if category == "complete":
        return open_ports

    return [
        item for item in open_ports
        if category in item.get("categories", [])
    ]


# ============================================================
# REPORTE TÉCNICO
# ============================================================

def format_service_line(item: dict) -> str:
    """
    Formatea una línea de servicio abierto.
    """

    port = item.get("port")
    protocol = item.get("protocol", "tcp")
    service = item.get("service", "unknown")
    product = item.get("product", "")
    version = item.get("version", "")
    extrainfo = item.get("extrainfo", "")
    categories = ", ".join(item.get("categories", []))

    details = " ".join(x for x in [product, version, extrainfo] if x).strip()

    if details:
        return f"- {port}/{protocol} - {service} - {details} - Categorías: {categories}"

    return f"- {port}/{protocol} - {service} - Categorías: {categories}"


def format_technical_report(scan_result: dict, category: str, filtered_services: list[dict]) -> str:
    """
    Genera reporte técnico fijo.
    """

    ip = scan_result.get("ip", "desconocida")
    host_status = scan_result.get("host_status", "unknown")
    all_open = scan_result.get("open_ports", [])

    lines = []

    lines.append("=== RESULTADO TÉCNICO NMAP ===")
    lines.append(f"IP objetivo: {ip}")
    lines.append(f"Estado del host según Nmap: {host_status}")
    lines.append("Escaneo realizado: todos los puertos TCP (-p-) con detección de servicios (-sV)")
    lines.append(f"Total de puertos abiertos detectados: {len(all_open)}")
    lines.append(f"Categoría solicitada para análisis: {CATEGORY_LABELS.get(category, category)}")
    lines.append(f"Servicios relevantes para la solicitud: {len(filtered_services)}")
    lines.append("")

    if scan_result.get("error"):
        lines.append(f"[!] Error: {scan_result.get('error')}")
        return "\n".join(lines)

    if not all_open:
        lines.append("No se detectaron puertos abiertos.")
        return "\n".join(lines)

    lines.append("Puertos abiertos detectados por Nmap:")
    for item in all_open:
        lines.append(format_service_line(item))

    lines.append("")

    if category != "complete":
        lines.append(f"Servicios filtrados para la categoría '{CATEGORY_LABELS.get(category, category)}':")
        if filtered_services:
            for item in filtered_services:
                lines.append(format_service_line(item))
        else:
            lines.append("- No se encontraron servicios abiertos asociados a esta categoría.")

    return "\n".join(lines)


# ============================================================
# ANÁLISIS DEL LLM
# ============================================================

def llm_analyze_result(user_prompt: str, scan_result: dict, category: str, filtered_services: list[dict]) -> str:
    """
    Usa el LLM solo para analizar resultados reales de Nmap.

    Regla importante:
    - Si el análisis es completo, el LLM recibe todos los puertos abiertos.
    - Si el análisis es por categoría, el LLM recibe SOLO los servicios filtrados.
    """

    if not USE_LLM_ANALYSIS:
        return ""

    # Si el usuario pidió análisis completo, se entregan todos los servicios.
    # Si pidió una categoría específica, se entregan solo los servicios filtrados.
    if category == "complete":
        services_for_llm = scan_result.get("open_ports", [])
        analysis_scope = "complete"
    else:
        services_for_llm = filtered_services
        analysis_scope = "filtered"

    llm_payload = {
        "user_request": user_prompt,
        "analysis_scope": analysis_scope,
        "analysis_category": category,
        "analysis_category_label": CATEGORY_LABELS.get(category, category),
        "target_ip": scan_result.get("ip"),
        "scan_type": scan_result.get("scan_type"),
        "services_to_analyze": services_for_llm,
        "total_open_ports_detected_by_nmap": scan_result.get("open_count", 0),
        "note": (
            "Nmap pudo detectar más puertos abiertos, pero para esta solicitud "
            "solo deben analizarse los servicios incluidos en services_to_analyze."
            if category != "complete"
            else "El usuario solicitó análisis completo, por lo tanto se analizan todos los servicios abiertos."
        )
    }

    prompt = f"""
Analiza el siguiente resultado técnico real de Nmap.

Datos permitidos para el análisis:
{json.dumps(llm_payload, indent=2, ensure_ascii=False)}

Instrucciones obligatorias:
- Responde en español.
- No inventes puertos, servicios, versiones, CVE ni vulnerabilidades confirmadas.
- Analiza únicamente los elementos dentro de "services_to_analyze".
- No analices puertos que no aparezcan en "services_to_analyze".
- Si "services_to_analyze" está vacío, indica que no se encontraron servicios relevantes para la categoría solicitada.
- Si la categoría solicitada es "db", analiza solo bases de datos.
- Si la categoría solicitada es "web", analiza solo servicios web.
- Si la categoría solicitada es "remote", analiza solo administración remota.
- Si la categoría solicitada es "admin", analiza solo servicios administrativos o sensibles.
- Si la categoría solicitada es "smb", analiza solo SMB o compartición de archivos.
- Si la categoría solicitada es "mail", analiza solo correo.
- Si la categoría solicitada es "dns", analiza solo DNS.
- Si la categoría solicitada es "ftp", analiza solo FTP.
- Diferencia entre exposición, riesgo potencial y vulnerabilidad confirmada.
- No entregues instrucciones de explotación.
- Entrega una respuesta práctica y breve.
- Usa estas secciones:
  1. Interpretación según la solicitud
  2. Servicios relevantes
  3. Riesgos potenciales
  4. Prioridad sugerida
  5. Siguiente paso defensivo recomendado
"""

    try:
        response = ollama.chat(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Eres un analista de seguridad defensiva. "
                        "Solo analizas los servicios entregados explícitamente en services_to_analyze. "
                        "No debes analizar puertos externos a esa lista. "
                        "No inventes datos y no entregues instrucciones ofensivas."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        return response["message"]["content"].strip()

    except Exception as e:
        return f"No se pudo generar análisis del LLM. Detalle: {e}"


# ============================================================
# FLUJO PRINCIPAL
# ============================================================

def print_json_if_enabled(scan_result: dict, filtered_services: list[dict]):
    """
    Muestra JSON solo si SHOW_JSON está activado.
    """

    if SHOW_JSON:
        print("")
        print("=== JSON TÉCNICO ===")
        print(json.dumps({
            "scan_result": scan_result,
            "filtered_services": filtered_services
        }, indent=2, ensure_ascii=False))


def run_agent(user_prompt: str):
    """
    Ejecuta el flujo:
        1. Extrae IP.
        2. Detecta intención.
        3. Ejecuta Nmap en todos los puertos.
        4. Filtra resultados según intención.
        5. Genera reporte técnico.
        6. LLM analiza según solicitud.
    """

    ip = extract_ip_from_text(user_prompt)

    if not ip:
        print("[!] No se detectó una IP válida en la solicitud.")
        print("Ejemplo:")
        print('  python secagentV3.py "Verifica servicios web de 10.10.1.129"')
        return

    category = detect_analysis_category(user_prompt)

    print("")
    print("=== SOLICITUD INTERPRETADA ===")
    print(f"IP detectada: {ip}")
    print(f"Tipo de análisis solicitado: {CATEGORY_LABELS.get(category, category)}")
    print("Nota: Nmap escaneará todos los puertos TCP y luego se filtrará el análisis según la solicitud.")

    scan_result = run_nmap_full_scan(ip)

    filtered_services = filter_services_by_category(scan_result, category)

    print("")
    print(format_technical_report(scan_result, category, filtered_services))

    if USE_LLM_ANALYSIS:
        print("")
        print("=== ANÁLISIS DEL LLM ===")
        print(llm_analyze_result(user_prompt, scan_result, category, filtered_services))

    print_json_if_enabled(scan_result, filtered_services)


# ============================================================
# ENTRADA PRINCIPAL
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_agent(" ".join(sys.argv[1:]))

    else:
        print(f"Agente listo con Nmap + Ollama. Modelo: {MODEL}")
        print("Ctrl+C para salir.")
        print("")
        print("Ejemplos:")
        print('  Verifica los servicios web de 10.10.1.129')
        print('  Analiza servicios de bases de datos en 10.10.1.129')
        print('  Revisa servicios administrativos expuestos en 10.10.1.129')
        print('  Realiza un análisis completo de 10.10.1.129')
        print('  Revisa servicios de correo en 10.10.1.129')
        print('  Revisa SMB en 10.10.1.129')

        while True:
            try:
                user_input = input("\n> ").strip()

                if not user_input:
                    continue

                run_agent(user_input)

            except (KeyboardInterrupt, EOFError):
                print("\nAdiós.")
                break
