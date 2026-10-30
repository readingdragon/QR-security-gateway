package com.qrsg.app.ui.main

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation3.runtime.NavKey

@Composable
fun MainScreen(
    onItemClick: (NavKey) -> Unit,
    modifier: Modifier = Modifier,
) {
    ScannerHomeScreen(
    onScanClick = { onItemClick(com.qrsg.app.Scanner) },
    modifier = modifier,
    )
}

@Composable
private fun ScannerHomeScreen(
    onScanClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "QR Security Gateway",
            style = MaterialTheme.typography.headlineLarge,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary,
        )

        Spacer(Modifier.height(8.dp))

        // Text(
        //     text = "QR Security Gateway",
        //     style = MaterialTheme.typography.titleMedium,
        // )

        Spacer(Modifier.height(32.dp))

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .height(220.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
            ),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text("⛶", style = MaterialTheme.typography.displayLarge)
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "QR scanner",
                    style = MaterialTheme.typography.titleLarge,
                )
                Text(
                    text = "Let me check it first.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        Spacer(Modifier.height(24.dp))

        Button(
            onClick = onScanClick,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Scan QR code")
        }

        Spacer(Modifier.height(12.dp))

        OutlinedButton(
            onClick = { /* History screen comes later */ },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Scan history")
        }

        Spacer(Modifier.height(24.dp))

        Text(
            text = "Check first. Open safely.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.secondary,
        )
    }
}
