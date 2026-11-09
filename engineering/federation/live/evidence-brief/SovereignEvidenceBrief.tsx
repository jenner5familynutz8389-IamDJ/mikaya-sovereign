import { useMemo, useState } from 'react';
import source from './evidence-brief.json';
import './sovereign-evidence-brief.css';

/** Public-facing derivative of the owner's original 4-section technical evidence brief.
 * The dataset is a dated, reviewed publication snapshot — NEVER live system attestation.
 * Do not connect this view directly to private device registries or wallet credentials.
 */
type EvidenceItem = (typeof source.sections)[number]['items'][number];
type EvidenceStatus = EvidenceItem['status'];
const STATUS_TEXT: Record<string, string> = {
  TESTED_AT_DATE: 'Tested at stated date',
  HISTORICAL_SOURCE: 'Historical source',
  DESIGN: 'Design / vision',
  NEEDS_REPRODUCTION: 'Needs reproduction',
  BLOCKED: 'Security / release hold',
  OWNER_REVIEW: 'Owner review needed',
  COUNSEL_REVIEW: 'Counsel review needed',
};
const STATUS_CATEGORY: Record<string, string> = {
  TESTED_AT_DATE: 'observed',
  HISTORICAL_SOURCE: 'history',
  DESIGN: 'vision',
  NEEDS_REPRODUCTION: 'hold',
  BLOCKED: 'hold',
  OWNER_REVIEW: 'review',
  COUNSEL_REVIEW: 'review',
};

function EvidenceCard({ item }: { item: EvidenceItem }) {
  const [open, setOpen] = useState(false);
  const label = STATUS_TEXT[item.status] ?? 'Unclassified';
  return (
    <article className="mi-evidence-item">
      <button type="button" className="mi-evidence-toggle" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="mi-chevron" aria-hidden="true">{open ? '−' : '+'}</span>
        <span className="mi-evidence-title">{item.claim}</span>
        <span className={'mi-evidence-status mi-status-' + (STATUS_CATEGORY[item.status] ?? 'review')}>{label}</span>
      </button>
      {open && (
        <div className="mi-evidence-detail">
          <p>{item.detail}</p>
          <dl>
            <dt>Evidence / source</dt><dd>{item.evidence}</dd>
            <dt>Next verification step</dt><dd>{item.next}</dd>
          </dl>
        </div>
      )}
    </article>
  );
}

export default function SovereignEvidenceBrief() {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({ provable: true });
  const [selected, setSelected] = useState('ALL');
  const statusList = useMemo(() => Array.from(new Set(source.sections.flatMap(section => section.items.map(item => item.status)))), []);
  const visibleCount = source.sections.flatMap(section => section.items).filter(item => selected === 'ALL' || item.status === selected).length;
  return (
    <main className="mi-evidence-page">
      <header className="mi-evidence-header">
        <p className="mi-eyebrow">MIKAYA-SOVEREIGN / INDEPENDENT ASSURANCE</p>
        <h1>{source.title}</h1>
        <p className="mi-evidence-subtitle">{source.subtitle}</p>
        <div className="mi-evidence-meta">
          <span>Snapshot: {source.preparedAt}</span>
          <span>Public review · no confidential hardware identity</span>
          <span>No wallet authority</span>
        </div>
      </header>
      <div className="mi-evidence-warning" role="note">
        <strong>Interpretation boundary.</strong> {source.verificationNote}
      </div>
      <div className="mi-evidence-controls">
        <label htmlFor="mi-evidence-status-filter">Show claims</label>
        <select id="mi-evidence-status-filter" value={selected} onChange={event => setSelected(event.target.value)}>
          <option value="ALL">All evidence categories</option>
          {statusList.map(status => <option key={status} value={status}>{STATUS_TEXT[status] ?? status}</option>)}
        </select>
        <span aria-live="polite">{visibleCount} claims</span>
      </div>
      <div className="mi-evidence-sections">
        {source.sections.map(section => {
          const items = section.items.filter(item => selected === 'ALL' || item.status === selected);
          if (items.length === 0) return null;
          const isOpen = Boolean(expanded[section.id]);
          return (
            <section key={section.id} className="mi-evidence-section" aria-label={section.label}>
              <button type="button" className="mi-section-toggle" aria-expanded={isOpen} onClick={() => setExpanded(prev => ({ ...prev, [section.id]: !prev[section.id] }))}>
                <span>{section.label}</span>
                <span className="mi-section-count">{items.length} items {isOpen ? '▲' : '▼'}</span>
              </button>
              {isOpen && <div className="mi-evidence-body"><p>{section.intro}</p>{items.map(item => <EvidenceCard key={item.id} item={item} />)}</div>}
            </section>
          );
        })}
      </div>
      <footer className="mi-evidence-footer">
        <strong>Additive development rule.</strong> Preserve original historical materials in the private archive; publish reviewed, dated derivatives in a separate source path. This brief does not verify patentability, legal immunity, external adoption, hardware attestation or monetary settlement.
      </footer>
    </main>
  );
}
