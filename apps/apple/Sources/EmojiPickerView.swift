import SwiftUI

/// Build 49: the app's own emoji picker. On iPhone/iPad a bottom sheet (`.emojiPickerSheet`), on
/// the Mac the content of a popover anchored to its button (the composer's emoji button, the
/// reaction "+"). A search field, recents, a category strip, and a grid that fills the width.
struct EmojiPickerView: View {
    let onPick: (String) -> Void
    var dismissOnPick = true
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @State private var recents: [String] = EmojiCatalog.recents()
    @State private var jump: String?

    private let columns = [GridItem(.adaptive(minimum: 40, maximum: 52), spacing: 4)]

    var body: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.white.opacity(0.5))
                TextField("Search emoji", text: $query)
                    .textFieldStyle(.plain).foregroundStyle(.white)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("emoji.search")
                if !query.isEmpty {
                    Button { query = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.white.opacity(0.4)) }
                        .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 12, style: .continuous))

            if query.isEmpty {
                // The category strip: jump to a section.
                HStack(spacing: 0) {
                    ForEach(EmojiCatalog.categories) { c in
                        Button { jump = c.id } label: {
                            Image(systemName: c.symbol).font(.system(size: 15))
                                .frame(maxWidth: .infinity, minHeight: 30)
                                .foregroundStyle(.white.opacity(0.65))
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(c.title)
                    }
                }
            }

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVGrid(columns: columns, alignment: .center, spacing: 4, pinnedViews: [.sectionHeaders]) {
                        if !query.isEmpty {
                            let found = EmojiCatalog.search(query)
                            if found.isEmpty {
                                Text("No emoji match “\(query)”").font(.footnote).foregroundStyle(.white.opacity(0.5))
                                    .gridCellColumns(8).padding(.top, 20)
                            }
                            ForEach(found, id: \.self) { cell($0) }
                        } else {
                            if !recents.isEmpty {
                                Section { ForEach(recents, id: \.self) { cell($0) } } header: { header("Recently used") }
                            }
                            ForEach(EmojiCatalog.categories) { c in
                                Section { ForEach(c.emoji, id: \.self) { cell($0) } } header: { header(c.title).id(c.id) }
                            }
                        }
                    }
                    .padding(.horizontal, 2).padding(.bottom, 12)
                }
                .onChange(of: jump) { _, id in
                    guard let id else { return }
                    withAnimation(.snappy(duration: 0.2)) { proxy.scrollTo(id, anchor: .top) }
                    jump = nil
                }
            }
        }
        .padding(.horizontal, 12).padding(.top, 14)
        .accessibilityIdentifier("emoji.picker")
    }

    private func header(_ title: String) -> some View {
        Text(title.uppercased())
            .font(.system(size: 11, weight: .semibold)).foregroundStyle(.white.opacity(0.5))
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 4)
            .background(.ultraThinMaterial.opacity(0.9))
    }

    private func cell(_ e: String) -> some View {
        Button {
            EmojiCatalog.noteUsed(e)
            onPick(e)
            if dismissOnPick { dismiss() } else { recents = EmojiCatalog.recents() }
        } label: {
            Text(e).font(.system(size: 28))
                .frame(maxWidth: .infinity, minHeight: 44)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(EmojiCatalog.name(e))
        .accessibilityIdentifier("emoji.\(e)")
    }
}

extension View {
    /// The emoji picker as a bottom sheet (iPhone/iPad).
    func emojiPickerSheet(isPresented: Binding<Bool>, onPick: @escaping (String) -> Void) -> some View {
        sheet(isPresented: isPresented) {
            EmojiPickerView(onPick: onPick)
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
                .presentationBackground(.ultraThinMaterial)
                .preferredColorScheme(.dark)
        }
    }
}
