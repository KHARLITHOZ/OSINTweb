/**
 * PDF export module — jsPDF + AutoTable.
 * Loaded only on pages that need it via {% block extra_scripts %}.
 */

/* Lazy-load jsPDF and autotable only when needed */
function _loadJsPDF(callback) {
  if (window.jspdf) { callback(); return; }

  const s1 = document.createElement('script');
  s1.src = 'https://unpkg.com/jspdf@2.5.1/dist/jspdf.umd.min.js';
  s1.crossOrigin = 'anonymous';
  s1.onload = () => {
    const s2 = document.createElement('script');
    s2.src = 'https://unpkg.com/jspdf-autotable@3.8.2/dist/jspdf.plugin.autotable.min.js';
    s2.crossOrigin = 'anonymous';
    s2.onload = callback;
    document.head.appendChild(s2);
  };
  document.head.appendChild(s1);
}

function _basePDF(title) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: 'p', unit: 'mm', format: 'a4' });

  // Header bar
  doc.setFillColor(7, 7, 14);
  doc.rect(0, 0, 210, 20, 'F');
  doc.setTextColor(79, 158, 255);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text('OSINTng', 10, 13);
  doc.setTextColor(200, 200, 220);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(title, 50, 13);
  doc.text(new Date().toLocaleString('es-ES'), 150, 13);

  doc.setTextColor(50, 50, 70);
  return doc;
}

function _download(doc, filename) {
  doc.save(filename);
}

/** Export IP result to PDF */
function generateIPPDF(data) {
  _loadJsPDF(() => {
    const doc = _basePDF(`Análisis IP: ${data.ip}`);
    doc.autoTable({
      startY: 28,
      head:   [['Campo', 'Valor']],
      body:   [
        ['IP',          data.ip          || '—'],
        ['País',        `${data.country} (${data.country_code})`],
        ['Región',      data.region      || '—'],
        ['Ciudad',      data.city        || '—'],
        ['ISP',         data.isp         || '—'],
        ['Organización',data.org         || '—'],
        ['ASN',         data.asn         || '—'],
        ['Zona horaria',data.timezone    || '—'],
        ['Proxy/VPN',   data.is_proxy  ? 'Sí' : 'No'],
        ['Hosting',     data.is_hosting? 'Sí' : 'No'],
        ['Reverse DNS', data.reverse_dns || '—'],
        ['Latitud',     String(data.latitude  ?? '—')],
        ['Longitud',    String(data.longitude ?? '—')],
      ],
      styles:      { fontSize: 9, cellPadding: 4 },
      headStyles:  { fillColor: [12, 12, 28], textColor: [79, 158, 255], fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [14, 14, 28] },
      bodyStyles:  { fillColor: [10, 10, 22], textColor: [200, 200, 220] },
    });
    _download(doc, `osint_ip_${data.ip}.pdf`);
  });
}

/** Export Domain result to PDF */
function generateDomainPDF(data) {
  _loadJsPDF(() => {
    const doc = _basePDF(`Análisis Dominio: ${data.domain}`);
    doc.autoTable({
      startY: 28,
      head:   [['Campo', 'Valor']],
      body:   [
        ['Dominio',     data.domain          || '—'],
        ['Registrar',   data.registrar        || '—'],
        ['Creación',    data.creation_date    || '—'],
        ['Expiración',  data.expiration_date  || '—'],
        ['IPs (A)',     (data.dns_a_list    || []).join(', ') || '—'],
        ['Name Servers',(data.name_servers_list||[]).join(', ') || '—'],
        ['MX',          (data.dns_mx_list   || []).join('\n') || '—'],
        ['SPF',         data.spf_record       || '—'],
        ['DMARC',       data.dmarc_record     || '—'],
        ['Subdominios', String((data.subdomains_list||[]).length)],
      ],
      styles:      { fontSize: 9, cellPadding: 4 },
      headStyles:  { fillColor: [12, 12, 28], textColor: [129, 140, 248], fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [14, 14, 28] },
      bodyStyles:  { fillColor: [10, 10, 22], textColor: [200, 200, 220] },
    });
    _download(doc, `osint_domain_${data.domain}.pdf`);
  });
}

/** Export Email result to PDF */
function generateEmailPDF(data) {
  _loadJsPDF(() => {
    const doc = _basePDF(`Análisis Email: ${data.email}`);
    doc.autoTable({
      startY: 28,
      head:   [['Campo', 'Valor']],
      body:   [
        ['Email',        data.email            || '—'],
        ['Dominio',      data.domain           || '—'],
        ['MX válido',    data.mx_valid ? 'Sí' : 'No'],
        ['Desechable',   data.is_disposable ? 'Sí' : 'No'],
        ['Nivel riesgo', data.risk_level       || '—'],
        ['Flags',        (data.risk_flags||[]).join('; ') || 'Ninguno'],
        ['Brechas HIBP', String(data.breach_count ?? 0)],
      ],
      styles:      { fontSize: 9, cellPadding: 4 },
      headStyles:  { fillColor: [12, 12, 28], textColor: [52, 211, 153], fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [14, 14, 28] },
      bodyStyles:  { fillColor: [10, 10, 22], textColor: [200, 200, 220] },
    });
    _download(doc, `osint_email_${data.email}.pdf`);
  });
}
