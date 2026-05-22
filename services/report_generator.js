const PDFDocument = require('pdfkit');
const crypto = require('crypto');

const { fetchAgencyDossierData } = require('./regulator_data');

// Visual tokens — kept here so the look-and-feel of generated PDFs stays
// consistent with the mobile app's primary-green theme.
const COLORS = {
  primary:     '#1B5E20',
  primaryDark: '#0D3311',
  primaryFade: '#E8F0E8',
  border:      '#CCD3CC',
  text:        '#222222',
  muted:       '#666666',
  accent:      '#FF8F00',
};

const FRENCH_STATUSES = {
  not_boarding: 'En attente',
  boarding:     "En cours d'embarquement",
  full:         'Complet',
  departed:     'Parti',
};

const FRENCH_ACTIONS = {
  seats_updated:     'Sièges mis à jour',
  status_changed:    'Statut changé',
  departure_created: 'Départ créé',
  staff_created:     'Agent créé',
  staff_deactivated: 'Agent désactivé',
  login_success:     'Connexion réussie',
  login_failed:      'Échec de connexion',
};

// French date+time formatter for the cover and footer. Africa/Douala
// matches the rest of the regulator surface and the app's session zone.
const dateTimeFmt = new Intl.DateTimeFormat('fr-FR', {
  dateStyle: 'long', timeStyle: 'medium', timeZone: 'Africa/Douala',
});
const dateFmt = new Intl.DateTimeFormat('fr-FR', {
  dateStyle: 'long', timeZone: 'Africa/Douala',
});

/// Generates a French-language Dossier d'agence PDF for the given period.
///
/// Returns `{ buffer, contentHash, data }`:
///   - buffer:      complete PDF bytes
///   - contentHash: SHA-256 hex of the buffer (32-byte / 64-char)
///   - data:        the dossier payload that was rendered (echoed back so
///                  the route handler can store it as the report's
///                  scope_json without re-querying)
///
/// The hash is NOT printed inside the PDF (that would create a recursion
/// problem). Instead it is returned to the API, displayed in the UI next
/// to the download button, and stored in generated_reports.content_hash.
/// A reviewer can verify by re-hashing the downloaded file.
async function generateAgencyDossierPdf({
  pool,
  agencyId,
  fromIso,
  toIso,
  reportId,
  generatedAt,
  generatedByName,
}) {
  const data = await fetchAgencyDossierData(pool, agencyId, fromIso, toIso);
  if (data === null) {
    const e = new Error('Agency not found');
    e.code = 'AGENCY_NOT_FOUND';
    throw e;
  }

  const buffer = await renderPdf({
    data, reportId, generatedAt, generatedByName,
  });
  const contentHash = crypto.createHash('sha256').update(buffer).digest('hex');

  return { buffer, contentHash, data };
}

function renderPdf({ data, reportId, generatedAt, generatedByName }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margin: 48,
      // bufferPages keeps every page in memory until doc.end(), which is
      // required for switchToPage() in drawFooterAllPages() to stamp the
      // footer on already-flushed pages.
      bufferPages: true,
      info: {
        Title:    `Dossier d'agence — ${data.agency.name}`,
        Author:   'NexBus Régulateur',
        Subject:  `Période du ${data.period.from} au ${data.period.to}`,
        Producer: 'NexBus PDF Generator',
        Creator:  'NexBus',
      },
    });

    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end',   () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // PDFKit auto-paginates when content exceeds the page; each new page
    // gets its own header strip via the 'pageAdded' event.
    let pageCount = 0;
    doc.on('pageAdded', () => {
      pageCount += 1;
      drawHeader(doc, pageCount === 1);
    });
    pageCount = 1;
    drawHeader(doc, true);

    drawCover(doc, data, reportId, generatedAt, generatedByName);
    drawKpiGrid(doc, data.metrics);
    drawStatusBreakdown(doc, data.statusBreakdown);
    drawTopRoutes(doc, data.topRoutes);
    drawRecentAudit(doc, data.recentAudit);

    drawFooterAllPages(doc, reportId, generatedAt, generatedByName);

    doc.end();
  });
}

// ─── Sections ───────────────────────────────────────────────────────────────

function drawHeader(doc, isFirstPage) {
  const w = doc.page.width;
  doc.save();
  doc.rect(0, 0, w, 28).fill(COLORS.primary);
  doc.fillColor('white').fontSize(10).font('Helvetica-Bold')
     .text('NEXBUS · Rapport régulateur', 48, 9, { align: 'left' });
  doc.fontSize(9).font('Helvetica')
     .text('CONFIDENTIEL', 48, 9, { align: 'right', width: w - 96 });
  doc.restore();
  doc.fillColor(COLORS.text);
  doc.y = 48;
  if (!isFirstPage) doc.moveDown(0.5);
}

function drawCover(doc, data, reportId, generatedAt, generatedByName) {
  doc.moveDown(1);
  doc.fontSize(22).font('Helvetica-Bold').fillColor(COLORS.primaryDark)
     .text("DOSSIER D'AGENCE", { align: 'left' });
  doc.moveDown(0.3);
  doc.fontSize(14).font('Helvetica').fillColor(COLORS.text)
     .text(data.agency.name);
  doc.moveDown(1);

  // Identity block (label-value pairs)
  drawKvBlock(doc, [
    ['Parc',        data.agency.parkName || '—'],
    ['Téléphone',   data.agency.contactPhone || '—'],
    ['Statut',      data.agency.isActive ? 'Active' : 'Inactive'],
    ['Période',     `${dateFmt.format(new Date(`${data.period.from}T00:00:00`))} → ${dateFmt.format(new Date(`${data.period.to}T00:00:00`))}`],
    ["Identifiant rapport", reportId],
    ["Généré le",   dateTimeFmt.format(generatedAt)],
    ["Généré par",  generatedByName || '—'],
  ]);

  doc.moveDown(1);
  drawSectionRule(doc);
}

function drawKpiGrid(doc, m) {
  doc.moveDown(0.5);
  drawSectionTitle(doc, 'INDICATEURS CLÉS');

  const cells = [
    { label: 'Départs',              value: m.departures.toString() },
    { label: 'Effectués',            value: m.departed.toString() },
    { label: 'Taux de remplissage',  value: `${(m.avgFillRate * 100).toFixed(0)} %` },
    {
      label: 'Ponctualité',
      // Same convention as the dossier screen: undefined when no
      // departures completed, surfaced as em-dash to avoid the
      // misleading "0 % on-time" reading.
      value: m.departed === 0 ? '—' : `${(m.onTimeRate * 100).toFixed(0)} %`,
    },
  ];

  const startX = 48;
  const cellW = (doc.page.width - 96 - 12) / 2;
  const cellH = 56;
  const rowGap = 8;

  cells.forEach((c, i) => {
    const col = i % 2;
    const row = (i / 2) | 0;
    const x = startX + col * (cellW + 12);
    const y = doc.y + row * (cellH + rowGap);
    doc.save();
    doc.rect(x, y, cellW, cellH).fillAndStroke(COLORS.primaryFade, COLORS.border);
    doc.fillColor(COLORS.primaryDark).font('Helvetica-Bold').fontSize(20)
       .text(c.value, x + 12, y + 10, { width: cellW - 24 });
    doc.fillColor(COLORS.muted).font('Helvetica').fontSize(10)
       .text(c.label, x + 12, y + 36, { width: cellW - 24 });
    doc.restore();
  });

  // Advance cursor past the grid (2 rows).
  doc.y = doc.y + 2 * (cellH + rowGap);
  doc.moveDown(0.5);
  drawSectionRule(doc);
}

function drawStatusBreakdown(doc, rows) {
  drawSectionTitle(doc, 'RÉPARTITION PAR STATUT');
  if (rows.length === 0) {
    drawMuted(doc, 'Aucun départ sur la période.');
    drawSectionRule(doc);
    return;
  }
  const total = rows.reduce((s, r) => s + r.count, 0);
  const colW = doc.page.width - 96;
  rows.forEach((r) => {
    const pct = total === 0 ? 0 : r.count / total;
    const label = FRENCH_STATUSES[r.status] || r.status;
    const y = doc.y;
    doc.font('Helvetica').fontSize(11).fillColor(COLORS.text)
       .text(label, 48, y, { continued: false, width: colW * 0.55 });
    doc.text(`${r.count}  ·  ${(pct * 100).toFixed(0)} %`,
             48 + colW * 0.55, y, { width: colW * 0.45, align: 'right' });
    // Progress bar
    const barY = y + 16;
    doc.save();
    doc.rect(48, barY, colW, 5).fill(COLORS.primaryFade);
    doc.rect(48, barY, colW * pct, 5).fill(COLORS.primary);
    doc.restore();
    doc.y = barY + 14;
  });
  doc.moveDown(0.5);
  drawSectionRule(doc);
}

function drawTopRoutes(doc, routes) {
  drawSectionTitle(doc, 'ROUTES PRINCIPALES');
  if (routes.length === 0) {
    drawMuted(doc, 'Aucune route active sur la période.');
    drawSectionRule(doc);
    return;
  }
  const colW = doc.page.width - 96;
  // Header row
  const yh = doc.y;
  doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.muted);
  doc.text('Route',                     48,                  yh, { width: colW * 0.60 });
  doc.text('Départs',                   48 + colW * 0.60,    yh, { width: colW * 0.20, align: 'right' });
  doc.text('Remplissage',               48 + colW * 0.80,    yh, { width: colW * 0.20, align: 'right' });
  doc.y = yh + 14;
  doc.moveTo(48, doc.y).lineTo(48 + colW, doc.y).strokeColor(COLORS.border).stroke();
  doc.y += 4;

  doc.font('Helvetica').fontSize(11).fillColor(COLORS.text);
  routes.forEach((r) => {
    const y = doc.y;
    doc.text(`${r.origin} → ${r.destination}`, 48, y, { width: colW * 0.60 });
    doc.text(r.departures.toString(),          48 + colW * 0.60, y, { width: colW * 0.20, align: 'right' });
    doc.text(`${(r.avgFillRate * 100).toFixed(0)} %`, 48 + colW * 0.80, y, { width: colW * 0.20, align: 'right' });
    doc.y = y + 16;
  });
  doc.moveDown(0.5);
  drawSectionRule(doc);
}

function drawRecentAudit(doc, entries) {
  drawSectionTitle(doc, 'AUDIT RÉCENT (20 derniers événements)');
  if (entries.length === 0) {
    drawMuted(doc, 'Aucun événement audité sur la période.');
    return;
  }
  doc.font('Helvetica').fontSize(10).fillColor(COLORS.text);
  const colW = doc.page.width - 96;
  entries.forEach((e) => {
    const y = doc.y;
    const when = dateTimeFmt.format(new Date(e.createdAt));
    const action = FRENCH_ACTIONS[e.action] || e.action;
    const stub = (e.entityId || '').slice(0, 8);
    doc.fillColor(COLORS.muted).text(when, 48, y, { width: colW * 0.32 });
    doc.fillColor(COLORS.text).text(action, 48 + colW * 0.32, y, { width: colW * 0.45 });
    doc.fillColor(COLORS.muted).font('Courier').fontSize(9)
       .text(`#${stub}`, 48 + colW * 0.77, y, { width: colW * 0.23, align: 'right' });
    doc.font('Helvetica').fontSize(10);
    doc.y = y + 14;
  });
}

function drawFooterAllPages(doc, reportId, generatedAt, generatedByName) {
  // Iterate every page that exists at end-time and stamp a footer.
  const pages = doc.bufferedPageRange();
  for (let i = pages.start; i < pages.start + pages.count; i++) {
    doc.switchToPage(i);
    const w = doc.page.width;
    const h = doc.page.height;
    doc.save();
    doc.fontSize(8).fillColor(COLORS.muted).font('Helvetica');
    doc.text(
      `Rapport ${reportId.slice(0, 8)}…  ·  ${dateTimeFmt.format(generatedAt)}  ·  ${generatedByName || '—'}`,
      48, h - 36, { width: w - 96, align: 'left' },
    );
    doc.text(
      `Page ${i - pages.start + 1} / ${pages.count}`,
      48, h - 36, { width: w - 96, align: 'right' },
    );
    doc.restore();
  }
}

// ─── Layout helpers ─────────────────────────────────────────────────────────

function drawSectionTitle(doc, title) {
  doc.font('Helvetica-Bold').fontSize(13).fillColor(COLORS.primaryDark)
     .text(title, 48, doc.y);
  doc.moveDown(0.3);
}

function drawSectionRule(doc) {
  doc.moveTo(48, doc.y + 4).lineTo(doc.page.width - 48, doc.y + 4)
     .strokeColor(COLORS.border).stroke();
  doc.moveDown(0.6);
}

function drawKvBlock(doc, pairs) {
  const labelW = 140;
  const valueX = 48 + labelW + 8;
  const valueW = doc.page.width - 48 - valueX;

  doc.font('Helvetica').fontSize(10);
  pairs.forEach(([k, v]) => {
    const y = doc.y;
    doc.fillColor(COLORS.muted).text(k, 48, y, { width: labelW });
    doc.fillColor(COLORS.text).text(String(v ?? '—'), valueX, y, { width: valueW });
    doc.y = Math.max(doc.y, y + 14);
  });
}

function drawMuted(doc, text) {
  doc.font('Helvetica').fontSize(10).fillColor(COLORS.muted)
     .text(text, 48, doc.y, { width: doc.page.width - 96 });
  doc.moveDown(0.4);
}

module.exports = { generateAgencyDossierPdf };
