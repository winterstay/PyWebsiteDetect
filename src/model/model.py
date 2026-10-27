import torch
import torch.nn as nn


def masked_mean_pooling(x: torch.Tensor, mask: torch.Tensor, dim: int):
    """
    x:    [..., L, D]
    mask: [..., L]
    """
    mask = mask.unsqueeze(-1).float()  # [..., L, 1]
    x = x * mask
    denom = mask.sum(dim=dim).clamp(min=1e-6)
    return x.sum(dim=dim) / denom


class AttentionPooling(nn.Module):
    """Attention-based MIL pooling (Ilse et al. 2018).

    Learns a scalar importance weight for each instance in a bag,
    then produces a weighted-sum bag representation.

    Returns both the pooled vector and the (softmax-normalised)
    attention weights so they can be inspected for interpretability.
    """

    def __init__(self, input_dim: int, hidden_dim: int = 128):
        super().__init__()
        self.attn = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, x: torch.Tensor, mask: torch.Tensor):
        """
        Args:
            x:    [B, S, D]  — instance representations
            mask: [B, S]     — 1 = valid, 0 = padding
        Returns:
            pooled: [B, D]  — attention-weighted bag representation
            weights: [B, S]  — softmax attention weights (sum to 1)
        """
        scores = self.attn(x).squeeze(-1)  # [B, S]
        # Mask padding: set to very negative so softmax → 0
        scores = scores.masked_fill(mask.float() == 0, float('-inf'))
        weights = torch.softmax(scores, dim=-1)  # [B, S]
        pooled = torch.sum(x * weights.unsqueeze(-1), dim=1)  # [B, D]
        return pooled, weights


class WebSeqModel(nn.Module):
    def __init__(
        self,
        node_type_vocab_size: int,
        api_name_vocab_size: int,
        html_element_info_vocab_size: int,
        calling_method_vocab_size: int,
        frame_owner_info_vocab_size: int,
        num_dim: int = 7,
        bin_dim: int = 5,
        multi_dim: int = 9,
        emb_dim: int = 32,
        lstm_hidden_dim: int = 128,
        lstm_layers: int = 1,
        dropout: float = 0.1,
    ):
        super().__init__()

        self.node_type_emb = nn.Embedding(node_type_vocab_size, emb_dim, padding_idx=0)
        self.api_name_emb = nn.Embedding(api_name_vocab_size, emb_dim, padding_idx=0)
        self.html_element_info_emb = nn.Embedding(html_element_info_vocab_size, emb_dim, padding_idx=0)
        self.calling_method_emb = nn.Embedding(calling_method_vocab_size, emb_dim, padding_idx=0)
        self.frame_owner_info_emb = nn.Embedding(frame_owner_info_vocab_size, emb_dim, padding_idx=0)

        input_dim = emb_dim * 5 + num_dim + bin_dim + multi_dim

        self.node_proj = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.ReLU(),
        )

        self.seq_encoder = nn.LSTM(
            input_size=128,
            hidden_size=lstm_hidden_dim,
            num_layers=lstm_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if lstm_layers > 1 else 0.0,
        )

        self.web_pooling = AttentionPooling(
            input_dim=lstm_hidden_dim * 2,
            hidden_dim=128,
        )

        self.classifier = nn.Sequential(
            nn.Linear(lstm_hidden_dim * 2, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 2)
        )

    def encode_nodes(
        self,
        node_type_ids,
        api_name_ids,
        html_element_info_ids,
        calling_method_ids,
        frame_owner_info_ids,
        num_feats,
        bin_feats,
        multi_feats,
    ):
        """
        输入 shape:
            [B, S, T] / [B, S, T, D]
        输出:
            node_repr: [B, S, T, 128]
        """
        node_type_e = self.node_type_emb(node_type_ids)                   # [B,S,T,E]
        api_name_e = self.api_name_emb(api_name_ids)
        html_info_e = self.html_element_info_emb(html_element_info_ids)
        calling_method_e = self.calling_method_emb(calling_method_ids)
        frame_owner_e = self.frame_owner_info_emb(frame_owner_info_ids)

        x = torch.cat(
            [
                node_type_e,
                api_name_e,
                html_info_e,
                calling_method_e,
                frame_owner_e,
                num_feats,
                bin_feats,
                multi_feats,
            ],
            dim=-1,
        )  # [B,S,T,input_dim]

        x = self.node_proj(x)  # [B,S,T,128]
        return x

    def encode_sequences(self, node_repr, seq_mask):
        """
        node_repr: [B,S,T,128]
        seq_mask:  [B,S,T]
        返回:
            seq_repr: [B,S,2H]
        """
        B, S, T, D = node_repr.shape

        x = node_repr.view(B * S, T, D)
        mask = seq_mask.view(B * S, T)

        lstm_out, _ = self.seq_encoder(x)  # [B*S, T, 2H]

        seq_repr = masked_mean_pooling(lstm_out, mask, dim=1)  # [B*S, 2H]
        seq_repr = seq_repr.view(B, S, -1)  # [B,S,2H]
        return seq_repr

    def forward(
        self,
        node_type_ids,
        api_name_ids,
        html_element_info_ids,
        calling_method_ids,
        frame_owner_info_ids,
        num_feats,
        bin_feats,
        multi_feats,
        seq_mask,
        web_mask,
    ):
        """
        输入:
            node_type_ids:         [B,S,T]
            api_name_ids:          [B,S,T]
            html_element_info_ids: [B,S,T]
            calling_method_ids:    [B,S,T]
            frame_owner_info_ids:  [B,S,T]
            num_feats:             [B,S,T,7]
            bin_feats:             [B,S,T,5]
            multi_feats:           [B,S,T,9]
            seq_mask:              [B,S,T]
            web_mask:              [B,S]
        输出:
            logits:       [B,2]   — 类别 logits
            attn_weights: [B,S]   — 每个 sequence 的注意力权重 (和为1)
        """
        node_repr = self.encode_nodes(
            node_type_ids=node_type_ids,
            api_name_ids=api_name_ids,
            html_element_info_ids=html_element_info_ids,
            calling_method_ids=calling_method_ids,
            frame_owner_info_ids=frame_owner_info_ids,
            num_feats=num_feats,
            bin_feats=bin_feats,
            multi_feats=multi_feats,
        )  # [B,S,T,128]

        seq_repr = self.encode_sequences(node_repr, seq_mask)  # [B,S,2H]

        web_repr, attn_weights = self.web_pooling(seq_repr, web_mask)  # [B,2H], [B,S]

        logits = self.classifier(web_repr)  # [B,2]
        return logits, attn_weights
