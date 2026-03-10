# Lupa Municipal 2026

## 82 municipios chilenos tienen sus bases de datos abiertas a internet

**Santiago, 10 de marzo de 2026.** Una auditoría automatizada sobre los 345 sitios web municipales de Chile reveló que **82 municipalidades** — el 24% del total — tienen el puerto de su base de datos MySQL directamente expuesto a internet, permitiendo que cualquier persona en el mundo intente conectarse a los registros de contribuyentes, trámites y datos personales de sus vecinos.

El hallazgo ocurre en la semana exacta de cambio de mando presidencial. La Ley Marco de Ciberseguridad N° 21.663 ya está en vigor, y obliga a todos los organismos del Estado a cumplir con medidas mínimas de seguridad. La ANCI puede multar hasta 40.000 UTM por incumplimiento.

Además, **50 municipios operan sin SSL válido** — lo que significa que los datos que sus vecinos ingresan en formularios en línea viajan sin cifrar por internet — y **7 municipios siguen corriendo PHP 5.x**, software sin parches de seguridad desde diciembre de 2018. 221 municipios tienen el panel de administración de su servidor (cPanel) accesible desde internet. Entre los municipios con MySQL expuesto: Antofagasta, La Serena, Viña del Mar, San Miguel y Vallenar.

El informe AMUCH 2024 ya advertía que el 68.7% de los municipios no tiene plan de respuesta ante incidentes. Esta auditoría técnica lo confirma: el problema es verificable desde cualquier computador con conexión a internet.

---

## Hallazgos principales

| Hallazgo | Municipios afectados |
|---|---|
| MySQL expuesto a internet (puerto 3306) | 82 |
| Sin SSL válido | 50 |
| cPanel accesible públicamente | 221 |
| PHP 5.x sin soporte desde 2018 | 7 |
| Puertos de riesgo alto expuestos (total) | 334 |
| PHP expuesto en cabeceras HTTP | 38 |
| Copyright ≥ 5 años | 23 |

## Metodología

Escaneo TCP + HTTP realizado el 10 de marzo de 2026 sobre 345 dominios municipales.

1. **SSL** — conexión TLS directa con fallback httpx.
2. **Puertos** — TCP connect a `21, 22, 80, 443, 2083, 2222, 3306, 3389, 5432, 6379, 8080, 9200, 27017`.
3. **Legacy** — GET de homepage, análisis de cabeceras HTTP + scraping de footer y meta generator.

Los datos crudos están disponibles en [`results.json`](results.json). Todo es reproducible.

## Estructura del repositorio

```
lupa-municipal-2026/
├── index.html      ← sitio web completo (autocontenido)
├── results.json    ← datos crudos del escaneo
├── scanner.py      ← script de auditoría
└── lupa/
    ├── ssl_check.py
    ├── legacy.py
    └── recon.py
```

## Uso

```bash
pip install httpx selectolax
python scanner.py
python scanner.py --no-recon      # sin escaneo de puertos
python scanner.py --workers 20 --timeout 15
```

## Autor

Felipe Carvajal Brown — [@fcarvajalbrown](https://github.com/fcarvajalbrown)
