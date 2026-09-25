from pathlib import Path

from rag.documents.mitre_parser import MitreAttackParser


MITRE_FILE = Path(
    "rag/documents/mitre/enterprise-attack.json"
)

OUTPUT_FILE = Path(
    "rag/documents/mitre/parsed_documents.jsonl"
)


def main():
    print("=" * 70)
    print("MITRE ATT&CK PARSER")
    print("=" * 70)

    print("\n[1/3] Loading MITRE ATT&CK dataset...")

    parser = MitreAttackParser(MITRE_FILE)

    documents = parser.parse()

    print(f"Techniques extracted: {len(documents):,}")

    if not documents:
        raise RuntimeError(
            "No MITRE ATT&CK techniques were extracted."
        )

    print("\n[2/3] Inspecting extracted knowledge...")

    for document in documents[:5]:
        print("-" * 70)
        print(f"ID      : {document.document_id}")
        print(f"Title   : {document.title}")
        print(f"Source  : {document.source}")
        print("Content preview:")
        print(document.content[:500])

    print("\n[3/3] Saving parsed documents...")

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        for document in documents:

            record = {
                "document_id": document.document_id,
                "title": document.title,
                "source": document.source,
                "content": document.content,
            }

            import json

            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )

    print(f"Saved to: {OUTPUT_FILE}")

    print("\n" + "=" * 70)
    print("MITRE PARSING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()